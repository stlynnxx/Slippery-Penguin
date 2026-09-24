from yattag import Doc
from rich.console import Console
import json


def generate_report(b_exp, default_binary=None):
    import json
    from yattag import Doc

    doc, tag, text = Doc().tagtext()

    # Pick first binary if none specified
    if default_binary is None and b_exp:
        default_binary = next(iter(b_exp.keys()))

    with tag('html', lang='en'):
        # === HEAD ===
        with tag('head'):
            with tag('meta', charset='utf-8'):
                pass
            with tag('meta', name='viewport', content='width=device-width, initial-scale=1.0'):
                pass
            with tag('title'):
                text('Slippery Penguin Report')

            with tag('style'):
                doc.asis('''
                    body { 
                        margin: 0;
                        padding: 20px;
                        background: #1a1a1a;
                        color: #00ff00;
                    }
                    .header {
                        text-align: center;
                        border: 2px solid #00ff00;
                        border-radius: 10px;
                        padding: 20px;
                        margin-bottom: 20px;
                    }
                    .section {
                        margin: 15px 0;
                        padding: 15px;
                        background: #000;
                        border-left: 4px solid darkgreen;
                        border-bottom: 4px solid darkgreen;
                    }
                    pre {
                        background: #1a1a1a;
                        color: #00ff00;
                        padding: 10px;
                        border-radius: 5px;
                        max-height: 200px;
                        overflow-y: scroll;
                        overflow-x: auto;
                    }
                    select { 
                        padding: 8px;
                        font-size: 14px;
                        margin-bottom: 20px;
                    }
                    h1, h2, h3 { 
                        color: #00ff00;
                    }
                ''')

        # === BODY ===
        with tag('body'):
            # Header
            with tag('div', klass='header'):
                with tag('h1'):
                    text('Slippery Penguin')
                with tag('p'):
                    text('Results Reporting')

            # Dropdown
            with tag('h2'):
                text('Binaries')
            with tag('select', id='binary-select'):
                for binary_path in sorted(b_exp.keys()):
                    display = binary_path.split('/')[-1]
                    selected = 'selected' if binary_path == default_binary else ''
                    with tag('option', value=binary_path, klass=selected):
                        text(f"{display}")

            # Results container (populated by JS)
            with tag('div', id='results'):
                pass

            # Embed JSON data
            with tag('script', id='all-data', type='application/json'):
                doc.asis(json.dumps(b_exp))

            # JavaScript for interactivity
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

