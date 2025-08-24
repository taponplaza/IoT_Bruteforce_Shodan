"""Functions for generating reports."""

from jinja2 import Environment, FileSystemLoader, select_autoescape
from pathlib import Path


def generate_report(results, template_path: str) -> str:
    """Generate an HTML report using a Jinja2 template."""
    template_path = Path(template_path)
    env = Environment(
        loader=FileSystemLoader(template_path.parent),
        autoescape=select_autoescape(["html", "xml"]),
    )
    template = env.get_template(template_path.name)
    return template.render(results=results)
