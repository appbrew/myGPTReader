import logging
import re
import os
from datetime import datetime
import requests
from urllib.parse import urlparse
from flask import Flask, request
from flask_apscheduler import APScheduler
from slack_bolt import App, BoltResponse
from slack_bolt.adapter.flask import SlackRequestHandler
from slack_bolt.error import BoltUnhandledRequestError
import concurrent.futures
from app.daily_hot_news import build_all_news_block
from app.gpt import get_answer_from_chatGPT, get_answer_from_llama_file, get_answer_from_llama_web, get_text_from_whisper, get_voice_file_from_text, index_cache_file_dir
from app.rate_limiter import RateLimiter
from app.user import get_user, is_premium_user, is_active_user, update_message_token_usage
from app.util import md5

class Config:
    SCHEDULER_API_ENABLED = True

executor = concurrent.futures.ThreadPoolExecutor(max_workers=20)

schedule_channel = "#daily-news"

app = Flask(__name__)

slack_app = App(
    token=os.environ.get("SLACK_TOKEN"),
    signing_secret=os.environ.get("SLACK_SIGNING_SECRET"),
    raise_error_for_unhandled_request=True
)
slack_handler = SlackRequestHandler(slack_app)
logging.getLogger("slack_bolt.App").setLevel(logging.ERROR)

@slack_app.error
def handle_errors(error):
    if isinstance(error, BoltUnhandledRequestError):
        return BoltResponse(status=200, body="")
    else:
        return BoltResponse(status=500, body="Something Wrong")

scheduler = APScheduler()
scheduler.api_enabled = True
scheduler.init_app(app)

@app.route("/", methods=["GET"])
def root():
    return "healthy"

@app.route("/slack/events", methods=["POST"])
def slack_events():
    return slack_handler.handle(request)

def insert_space(text):

    # Handling the case between English words and Chinese characters
    text = re.sub(r'([a-zA-Z])([\u4e00-\u9fa5])', r'\1 \2', text)
    text = re.sub(r'([\u4e00-\u9fa5])([a-zA-Z])', r'\1 \2', text)

    # Handling the situation between numbers and Chinese
    text = re.sub(r'(\d)([\u4e00-\u9fa5])', r'\1 \2', text)
    text = re.sub(r'([\u4e00-\u9fa5])(\d)', r'\1 \2', text)

    # handling the special characters
    text = re.sub(r'([\W_])([\u4e00-\u9fa5])', r'\1 \2', text)
    text = re.sub(r'([\u4e00-\u9fa5])([\W_])', r'\1 \2', text)

    text = text.replace('  ', ' ')

    return text

thread_message_history = {}
MAX_THREAD_MESSAGE_HISTORY = 10

def update_thread_history(thread_ts, message_str=None, urls=None, file=None):
    if urls is not None:
        thread_message_history[thread_ts]['context_urls'].update(urls)
    if message_str is not None:
        if thread_ts in thread_message_history:
            dialog_texts = thread_message_history[thread_ts]['dialog_texts']
            dialog_texts.append(message_str)
            if len(dialog_texts) > MAX_THREAD_MESSAGE_HISTORY:
                dialog_texts = dialog_texts[-MAX_THREAD_MESSAGE_HISTORY:]
            thread_message_history[thread_ts]['dialog_texts'] = dialog_texts
        else:
            thread_message_history[thread_ts]['dialog_texts'] = [message_str]
    if file is not None:
        thread_message_history[thread_ts]['file'] = file

def extract_urls_from_event(event):
    if 'blocks' not in event:
        return None
    urls = set()
    for block in event['blocks']:
        for element in block['elements']:
            for e in element['elements']:
                if e['type'] == 'link':
                    url = urlparse(e['url']).geturl()
                    urls.add(url)
    return list(urls)

filetype_extension_allowed = ['epub', 'pdf', 'text', 'docx', 'markdown', 'm4a', 'webm', 'mp3', 'wav']
filetype_voice_extension_allowed = ['m4a', 'webm', 'mp3', 'wav']
max_file_size = 3 * 1024 * 1024

limiter_message_per_user = 5
limiter_time_period = 24 * 3600
limiter = RateLimiter(limit=limiter_message_per_user, period=limiter_time_period)

def dialog_context_keep_latest(dialog_texts, max_length=1):
    if len(dialog_texts) > max_length:
        dialog_texts = dialog_texts[-max_length:]
    return dialog_texts

def remove_url_from_text(text, urls):
    # only remove youtube url
    for url in urls:
        if 'youtube.com' in url or 'youtu.be' in url:
            text = text.replace('<' + url + '>', '')
    return text

def format_dialog_text(text, voicemessage=None):
    if text is None:
        return voicemessage if voicemessage else ''
    return insert_space(text.replace("<@U051JKES6Q1>", "")) + ('\n' + voicemessage if voicemessage else '')

def generate_message_id(channel, thread_ts):
    return f"{channel}-{thread_ts}"

def update_token_usage(event, total_llm_model_tokens, total_embedding_model_tokens):
    logging.info("=====> Start to update token usage!")
    try:
        user = event["user"]
        message_id = generate_message_id(event["channel"], event["ts"])
        message_type = 'text' if 'text' in event else 'file'
        if 'files' in event:
             filetype = event['files'][0]["filetype"]
             if filetype in filetype_voice_extension_allowed:
                message_type = 'voice'
        result = update_message_token_usage(user, message_id, message_type, total_llm_model_tokens, total_embedding_model_tokens)
        if not result:
            logging.error(f"Failed to update message token usage for {message_id}")
    except Exception as e:
        logging.error(e)

def bot_process(event, say, logger):
    user = event["user"]
    thread_ts = event["ts"]
    channel = event["channel"]

    file_md5_name = None
    voicemessage = None

    if event.get('files'):
        file = event['files'][0] # only support one file for one thread
        logger.info('=====> Received file:')
        logger.info(file)
        filetype = file["filetype"]
        if filetype not in filetype_extension_allowed:
            say(f'<@{user}>, this filetype is not supported, please upload a file with extension [{", ".join(filetype_extension_allowed)}]', thread_ts=thread_ts)
            return
        if file["size"] > max_file_size:
            say(f'<@{user}>, this file size is beyond max file size limit ({max_file_size / 1024 /1024}MB)', thread_ts=thread_ts)
            return
        url_private = file["url_private"]
        temp_file_path = index_cache_file_dir / user
        temp_file_path.mkdir(parents=True, exist_ok=True)
        temp_file_filename = temp_file_path / file["name"]
        with open(temp_file_filename, "wb") as f:
            response = requests.get(url_private, headers={"Authorization": "Bearer " + slack_app.client.token})
            f.write(response.content)
            logger.info(f'=====> Downloaded file to save {temp_file_filename}')
            temp_file_md5 = md5(temp_file_filename)
            file_md5_name = index_cache_file_dir / (temp_file_md5 + '.' + filetype)
            if not file_md5_name.exists():
                logger.info(f'=====> Rename file to {file_md5_name}')
                temp_file_filename.rename(file_md5_name)
                if filetype in filetype_voice_extension_allowed:
                    voicemessage = get_text_from_whisper(file_md5_name)

    parent_thread_ts = event["thread_ts"] if "thread_ts" in event else thread_ts
    if parent_thread_ts not in thread_message_history:
        thread_message_history[parent_thread_ts] = { 'dialog_texts': [], 'context_urls': set(), 'file': None}

    if "text" in event or voicemessage:
        urls = extract_urls_from_event(event)
        logger.info(f'=====> Extracted urls from event: {urls}')
        try:
            dialog = remove_url_from_text(format_dialog_text(event["text"], voicemessage), urls)
            logger.info(f'=====> Formatted dialog: {dialog}')
            update_thread_history(parent_thread_ts, f'User: {dialog}', urls)
        except Exception as e:
            logger.error(e)
            say(f'<@{user}>, something went wrong, please try again later', thread_ts=thread_ts)
            return

    if file_md5_name is not None:
        if not voicemessage:
            update_thread_history(parent_thread_ts, None, None, file_md5_name)

    urls = thread_message_history[parent_thread_ts]['context_urls']
    file = thread_message_history[parent_thread_ts]['file']

    logger.info('=====> Current thread conversation messages are:')
    logger.info(thread_message_history[parent_thread_ts])

    # TODO: https://github.com/jerryjliu/llama_index/issues/778
    # if it can get the context_str, then put this prompt into the thread_message_history to provide more context to the chatGPT
    if file is not None:
        future = executor.submit(get_answer_from_llama_file, dialog_context_keep_latest(thread_message_history[parent_thread_ts]['dialog_texts']), file)
    elif len(urls) > 0:
        future = executor.submit(get_answer_from_llama_web, thread_message_history[parent_thread_ts]['dialog_texts'], list(urls))
    else:
        future = executor.submit(get_answer_from_chatGPT, thread_message_history[parent_thread_ts]['dialog_texts'])

    try:
        gpt_response = future.result(timeout=300)
        update_thread_history(parent_thread_ts, 'Assistant: %s' % insert_space(f'{gpt_response}'))
        gpt_response = gpt_response.replace("Assistant: ", "")
        logger.info(gpt_response)
        if voicemessage is None:
            say(f'<@{user}>, {gpt_response}', thread_ts=thread_ts)
        else:
            voice_file_path = get_voice_file_from_text(str(gpt_response))
            logger.info(f'=====> Voice file path is {voice_file_path}')
            slack_app.client.files_upload_v2(file=voice_file_path, channel=channel, thread_ts=parent_thread_ts)
    except concurrent.futures.TimeoutError:
        future.cancel()
        err_msg = 'Task timedout(5m) and was canceled.'
        logger.warning(err_msg)
        say(f'<@{user}>, {err_msg}', thread_ts=thread_ts)

@slack_app.event("app_mention")
def handle_mentions(event, say, logger):
    logger.info(event)

    bot_process(event, say, logger)

def bot_messages(message, next):
    logging.info(message)
    subtype = message.get("subtype")
    channel_type = message.get("channel_type")
    if channel_type == 'im' and (subtype is None or subtype == "file_share" or subtype == "message_changed"):
        logging.info(f"This is a message to bot: {message}")
        next()

@slack_app.event(event="message", middleware=[bot_messages])
def log_message(logger, event, say):
    try:
        bot_process(event, say, logger)
    except Exception as e:
        logger.error(f"Error responding to direct message: {e}")

@slack_app.event(event="team_join")
def send_welcome_message(logger, event):
    try:
        logger.info(f"Welcome new user: {event}")
    except Exception as e:
        logger.error(f"Error sending welcome message: {e}")

@slack_app.event("app_home_opened")
def update_home_tab(client, event, logger):
    try:
        logger.info("aaa")
    except Exception as e:
        logger.error(f"Error publishing home tab: {e}")

scheduler.start()

if __name__ == '__main__':
    app.run(debug=True)
