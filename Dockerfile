FROM python:3.11.2-slim

RUN mkdir -p /home/pwuser/myGPTReader
WORKDIR /home/pwuser/myGPTReader

COPY requirements.txt /home/pwuser/myGPTReader

RUN pip3 install --upgrade pip
RUN pip3 install -r /home/pwuser/myGPTReader/requirements.txt

COPY . /home/pwuser/myGPTReader

EXPOSE 3000
ENV PYTHONPATH /home/pwuser/myGPTReader
CMD [ "gunicorn", "app.server:app", "-b", "0.0.0.0:3000"]
