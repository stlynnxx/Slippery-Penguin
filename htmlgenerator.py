from yattag import Doc
from rich.console import Console
import datetime

def generate_report(b, r):
    doc, tag, text = Doc().tagtext()
    with tag('html'):
        with tag('body'):
            with tag('div'):
                with tag('p'):
                    text(f"{b} results: ")
                    doc.stag('br')
                    text(r)
    html_content = doc.getvalue()
    return html_content




