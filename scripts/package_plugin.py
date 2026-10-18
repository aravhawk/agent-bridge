"""Package the existing private plugin; never uploads or installs it."""
import json
from pathlib import Path
import zipfile

root = Path(__file__).resolve().parents[1]
source = root / 'plugin'
manifest = json.loads((source / 'plugin.json').read_text())
out = root / '.reports' / ('plugin-' + manifest['version'] + '.zip')
out.parent.mkdir(parents=True, exist_ok=True)
expected = ['plugin.json', 'mcp.json', '.codex-plugin/plugin.json', '.mcp.json']
with zipfile.ZipFile(out, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
    for name in expected:
        path = source / name
        if path.is_symlink():
            raise RuntimeError('Plugin symlinks are not permitted')
        json.loads(path.read_text())
        archive.write(path, manifest['name'] + '/' + name)
print(out)
