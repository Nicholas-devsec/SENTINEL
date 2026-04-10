from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from jinja2 import Environment, StrictUndefined
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail


EMAIL_TEMPLATE = """
<html>
  <body>
    <h1>SENTINEL Daily Digest</h1>
    <p>{{ generated_at }}</p>
    <table border="1" cellpadding="6" cellspacing="0">
      <thead>
        <tr>
          <th>IOC</th>
          <th>Type</th>
          <th>Source</th>
          <th>Score</th>
          <th>Severity</th>
          <th>ATT&CK</th>
        </tr>
      </thead>
      <tbody>
      {% for item in items %}
        <tr>
          <td>{{ item.value }}</td>
          <td>{{ item.type }}</td>
          <td>{{ item.source }}</td>
          <td>{{ "%.2f"|format(item.risk_score) }}</td>
          <td>{{ item.severity }}</td>
          <td>{{ ", ".join(item.mitre_techniques) if item.mitre_techniques else "None" }}</td>
        </tr>
      {% endfor %}
      </tbody>
    </table>
  </body>
</html>
""".strip()


@dataclass(slots=True)
class DigestMessage:
    subject: str
    html: str
    recipients: list[str]


def render_daily_digest(items: list[dict[str, Any]], *, generated_at: str) -> str:
    environment = Environment(undefined=StrictUndefined, trim_blocks=True, lstrip_blocks=True)
    template = environment.from_string(EMAIL_TEMPLATE)
    return template.render(items=items, generated_at=generated_at)


async def send_daily_digest(
    *,
    sendgrid_client: SendGridAPIClient,
    email_from: str,
    recipients: list[str],
    subject: str,
    html: str,
) -> Any:
    message = Mail(
        from_email=email_from,
        to_emails=recipients,
        subject=subject,
        html_content=html,
    )
    return sendgrid_client.send(message)
