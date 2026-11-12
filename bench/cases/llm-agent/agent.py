import json
import sqlite3
import subprocess

import anthropic

client = anthropic.Anthropic()
db = sqlite3.connect("crm.db")

ALLOWED = {"list_customers": "SELECT id, name FROM customers", "count_orders": "SELECT COUNT(*) FROM orders"}


def ask(prompt):
    resp = client.messages.create(
        model="claude-haiku-5-5",
        max_tokens=512,
        messages=[{"role": "user", "content": prompt}],
    )
    return resp.content[0].text


def run_shell_task(task):
    resp = client.messages.create(
        model="claude-haiku-5-5",
        max_tokens=256,
        messages=[{"role": "user", "content": f"Write one bash command to: {task}"}],
    )
    command = resp.content[0].text
    # expect: py-llm-output-to-dangerous-sink
    return subprocess.run(command, shell=True, capture_output=True).stdout


def answer_with_sql(question):
    resp = client.messages.create(
        model="claude-haiku-5-5",
        max_tokens=256,
        messages=[{"role": "user", "content": f"SQL for: {question}"}],
    )
    sql = resp.content[0].text
    # expect: py-llm-output-to-dangerous-sink
    return db.execute(sql).fetchall()


def answer_with_tool(question):
    # Safe: model picks from an allow-list via structured JSON; SQL text is ours.
    resp = client.messages.create(
        model="claude-haiku-5-5",
        max_tokens=128,
        messages=[{"role": "user", "content": f'Reply as {{"action": ...}} for: {question}'}],
    )
    action = json.loads(resp.content[0].text).get("action")
    if action not in ALLOWED:
        raise ValueError("unsupported action")
    return db.execute(ALLOWED[action]).fetchall()
