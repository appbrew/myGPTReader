import os
from jinja2 import Environment, FileSystemLoader, select_autoescape


def current_directory() -> str:
    return os.path.dirname(os.path.abspath(__file__))


def write_to_file(content: str) -> None:
    file = open(os.path.join(current_directory(), "task_definition.json"), "w")
    file.write(content)
    file.close()


if __name__ == "__main__":

    environment_whitelist = [
        "OPENAI_API_KEY",
        "SLACK_TOKEN",
        "SLACK_SIGNING_SECRET"
    ]
    environment_variables = {key: os.environ.get(key) for key in environment_whitelist}

    environment = Environment(
        loader=FileSystemLoader(current_directory(), encoding="utf8"),
        autoescape=select_autoescape(["html", "xml"]),
    )
    output = environment.get_template("task_definition.json.j2").render(
        image_id=os.environ.get("CIRCLE_BUILD_NUM"),
        environment_variables=environment_variables,
    )

    write_to_file(output)
