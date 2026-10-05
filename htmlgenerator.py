from yattag import Doc
from rich.console import Console
import json


def generate_PDF(b_exp):
    try:
        with open('art.txt', 'r') as f:
            ascii_art = f.read()
    except FileNotFoundError:
        ascii_art = ""
    doc, tag, text = Doc().tagtext()
    with tag('html', lang='en'):
        with tag('head'):
            with tag('meta', charset='utf-8'):
                pass
            with tag('title'):
                text('Slippery Penguin PDF Report')


            with tag('style'):
                doc.asis('''
                @page {
                    margin: 0.5cm;              
                    size: Letter;                 
                    @top-right {
                        content: "Page " counter(page) " of " counter(pages);}}
''')

            with tag('style'):
                doc.asis(f'''
                    body::before {{
                        position: fixed;
                        bottom: 5px;
                        top: 50%;
                        left: 50%;
                        transform: translate(-50%, 0);
                        font-family: monospace;
                        font-size: 10px;
                        line-height: 8px;
                        color: rgba(0, 100, 0, 0.05);  
                        white-space: pre;
                        z-index: 0;
                        pointer-events: none;
                        width: 100%;      
                        text-align: center; 
                    }}

                    body {{
                        margin: 10;
                        padding: 20px;
                        background: #1a1a1a;
                        color: #00ff00;
                    }}

                    .header {{
                        text-align: center;
                        border: 2px solid green;
                        border-radius: 10px;
                        padding: 20px;
                        margin-bottom: 20px;
                        background: black;
                        page-break-after: avoid;
                    }}
                    .section {{
                        margin: 0;         
                        padding: 8px;    
                        background: #000;
                        border-left: 4px solid darkgreen;
                        border-bottom: 4px solid darkgreen;
                        border-right: 4px solid darkgreen;
                        border-top: 4px solid darkgreen;
                        border-left: 4px solid darkgreen;
                        border-radius: 10px;
                        page-break-after: always;  
                        page-break-inside: avoid;
                    }}

                    .binary-title {{
                        color: #00ff00;
                        border-bottom: 1px solid #00ff00;
                        padding-bottom: 8px;
                        margin-top: 20px;
                    }}

                    .result-block {{
                        margin: 5px 0;
                        padding: 10px;
                        background: #111;
                        border-left: 1px dashed darkgreen;
                        border-bottom: 1px dashed darkgreen;
                        border-radius: 4px;
                        page-break-inside: avoid;
                    }}

                    .result-label {{
                        font-weight: bold;
                        color: #00cc00;
                        margin-bottom: 5px;
                    }}

                    pre {{
                        background: #1a1a1a;
                        color: #00ff00;
                        padding: 10px;
                        border-radius: 5px;
                          
                        overflow: hidden;   
                        margin: 0;
                        font-size: 10px;
                    }}

                    h1, h2, h3 {{
                        color: #00ff00;
                    }}
                ''')

        with tag('body'):
            # Header
            with tag('div', klass='header'):
                with tag('h1'):
                    text('Slippery Penguin')
                with tag('p'):
                    text('Results Reporting')

            # Binary Results
            if not b_exp:
                with tag('p'):
                    text('No results available')
            for binary_path in sorted(b_exp.keys()):
                with tag('div', klass='section'):
                    with tag('h3', klass='binary-title'):
                        text(binary_path)
                    binary_data = b_exp[binary_path]

                    #with tag('pre'):
                    #    strings = binary_data.get("strings", [])
                    #    if strings:
                    #        for s in strings:
                    #            text(s)
                    #            doc.stag('br')
                    #    else:
                    #        text("No data")


                    with tag('div', klass='result-block'):
                        with tag('div', klass='result-label'):
                            text('Flags:')
                        with tag('pre'):
                            flags = binary_data.get("flags", [])
                            if not flags:
                                text("No results available")
                            elif isinstance(flags, list):
                                for flag in flags[:20]:
                                    if isinstance(flag, dict):
                                        display = flag.get('string', 'N/A') + flag.get('severity', 'N/A')
                                        if display:
                                            text(f"{flag.get('string', 'N/A')} ({flag.get('severity', 'N/A')})\n")
                                        else:
                                            text(flags if flags else "No data")

                    with tag('div', klass='result-block'):
                        with tag('div', klass='result-label'):
                            text('Strace:')
                        with tag('pre'):
                            strace = binary_data.get("strace", [])
                            if not strace:
                                text("No results available")
                            elif isinstance(strace, list):
                                text('\n'.join(str(s) for s in strace[:50]))
                            else:
                                text(strace if strace else "No data")

                    with tag('div', klass='result-block'):
                        with tag('div', klass='result-label'):
                            text('GTFOBins Matches:')
                        with tag('pre'):
                            gtfo = binary_data.get("gtfo", [])
                            if not gtfo:
                                text("No results available")
                            elif isinstance(gtfo, list):
                                text('\n'.join(str(s) for s in gtfo[:50]))
                            else:
                                text(gtfo if gtfo else "No data")

                    with tag('div', klass='result-block'):
                        with tag('div', klass='result-label'):
                            text('Timeouts:')
                        with tag('pre'):
                            timeouts = binary_data.get("timeouts", [])
                            if not timeouts:
                                text("No results available")
                            elif isinstance(timeouts, list):
                                text('\n'.join(str(t) for t in timeouts[:50]))
                            else:
                                text(timeouts if timeouts else "No data")

    return doc.getvalue()

def generate_report(b_exp, default_binary=None):
    try:
        with open('art.txt', 'r') as f:
            ascii_art = f.read()
    except FileNotFoundError:
        ascii_art = ""

    doc, tag, text = Doc().tagtext()

    if default_binary is None and b_exp:
        default_binary = next(iter(b_exp.keys()))

    with tag('html', lang='en'):
        with tag('head'):
            with tag('meta', charset='utf-8'):
                pass
            with tag('meta', name='viewport', content='width=device-width, initial-scale=1.0'):
                pass
            with tag('title'):
                text('Slippery Penguin Report')

            with tag('style'):
                encoded = ascii_art.replace('\n', '\\A').replace('"', '\\"')
                doc.asis(f'''
                      body::before {{
                        content: "{encoded}";
                        position: fixed;
                        top: 88%;  
                        left: 90%;
                        transform: translate(-50%, -50%);
                        font-family: monospace;
                        font-size: 10px;
                        line-height: 8px;
                        color: gba(0, 100, 0, 0.1);  
                        white-space: pre;
                        z-index: 0;  
                        pointer-events: none;
                        max-width: 80vw;
                        overflow: hidden;
                    }}

                    body {{ 
                        margin: 0;
                        padding: 20px;
                        background: #1a1a1a;
                        color: #00ff00;
                        position: relative;  
                    }}
                    .header {{
                        text-align: center;
                        border: 2px solid green;
                        border-radius: 10px;
                        padding: 20px;
                        margin-bottom: 20px;
                        background: black;
                        
                    }}
                    .section {{
                        margin: 15px 0;
                        padding: 15px;
                        background: #000;
                        border-left: 4px solid darkgreen;
                        border-bottom: 4px solid darkgreen;
                        
                    }}
                    pre {{
                        background: #1a1a1a;
                        color: #00ff00;
                        padding: 10px;
                        border-radius: 5px;
                        max-height: 200px;
                        overflow-y: scroll;
                        overflow-x: auto;
                    }}
                    select {{ 
                        padding: 8px;
                        font-size: 14px;
                        margin-bottom: 20px;
                    }}
                    h1, h2, h3 {{ 
                        color: #00ff00;
                    }}
                ''')

        with tag('body'):
            # Header
            with tag('div', klass='header'):
                with tag('h1'):
                    text('Slippery Penguin')
                with tag('p'):
                    text('Results Reporting')

            # Dropdown
            with tag('h2'):
                text('Binaries:')
            with tag('select', id='binary-select'):
                for binary_path in sorted(b_exp.keys()):
                    display = binary_path.split('/')[-1]
                    selected = 'selected' if binary_path == default_binary else ''
                    with tag('option', value=binary_path, klass=selected):
                        text(f"{display}")


            with tag('div', id='results'):
                pass
            with tag('script', id='all-data', type='application/json'):
                doc.asis(json.dumps(b_exp))

            # JavaScript
            js_code = '''
            <script>
            (function() {
                const select = document.getElementById('binary-select');
                const resultsDiv = document.getElementById('results');
                const allData = JSON.parse(document.getElementById('all-data').textContent);

                function render(binary) {
                    const data = allData[binary] || {};
                    resultsDiv.innerHTML = '';

                    ['strings', 'strace', 'flags', 'gtfo'].forEach(function(type) {
                        const section = document.createElement('div');
                        section.className = 'section';

                        const heading = document.createElement('h3');
                        heading.textContent = type.charAt(0).toUpperCase() + type.slice(1);
                        section.appendChild(heading);

                        const content = data[type] || [];
                        if (content.length > 0) {
                            const pre = document.createElement('pre');
                            pre.textContent = content.slice(0, 50).join('\\n');
                            section.appendChild(pre);
                        } else {
                            const msg = document.createElement('p');
                            msg.textContent = 'No results';
                            section.appendChild(msg);
                        }

                        resultsDiv.appendChild(section);
                    });
                }

                select.addEventListener('change', function() {
                    render(this.value);
                });

                render(select.value);
            })();
            </script>
            '''
            doc.asis(js_code)

    return doc.getvalue()

