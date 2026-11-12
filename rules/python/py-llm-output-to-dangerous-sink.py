import json
import os
import subprocess

import anthropic
from openai import OpenAI

claude = anthropic.Anthropic()
oai = OpenAI()


def run_agent_step(task):
    msg = claude.messages.create(
        model="claude-sonnet-5-5",
        max_tokens=512,
        messages=[{"role": "user", "content": f"Write one shell command to: {task}"}],
    )
    command = msg.content[0].text
    # ruleid: py-llm-output-to-dangerous-sink
    subprocess.run(command, shell=True)


def analyst(question, cur):
    resp = oai.chat.completions.create(model="gpt-x", messages=[{"role": "user", "content": question}])
    sql = resp.choices[0].message.content
    # ruleid: py-llm-output-to-dangerous-sink
    cur.execute(sql)
    return cur.fetchall()


def calculator(expr, chain):
    answer = chain.invoke({"q": expr})
    # ruleid: py-llm-output-to-dangerous-sink
    return eval(answer)


def safe_structured(task):
    msg = claude.messages.create(model="claude-sonnet-5-5", max_tokens=256, messages=[{"role": "user", "content": task}])
    action = json.loads(msg.content[0].text)
    if action["name"] in {"status", "uptime"}:
        # ok: py-llm-output-to-dangerous-sink
        subprocess.run([action["name"]], check=False)


def safe_param(question, cur):
    resp = oai.chat.completions.create(model="gpt-x", messages=[{"role": "user", "content": question}])
    label = resp.choices[0].message.content
    # ok: py-llm-output-to-dangerous-sink
    cur.execute("INSERT INTO labels (text) VALUES (?)", (label,))


def safe_print(task):
    msg = claude.messages.create(model="claude-sonnet-5-5", max_tokens=256, messages=[{"role": "user", "content": task}])
    # ok: py-llm-output-to-dangerous-sink
    os.system("echo done")
    return msg.content[0].text
