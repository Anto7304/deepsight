"""Compare protected authentication functions to the supplied archive; no secret values are printed."""
import ast
import hashlib
import json
from pathlib import Path
import sys
import zipfile
archive=Path(sys.argv[1])
protected={'app/security.py':['hash_password','verify_password','make_token','current_user','require'],
           'app/api.py':['login','me','roles','users','create_user','patch_user'], 'app/main.py':['ensure_admin']}
with zipfile.ZipFile(archive) as z:
    results={}
    for file,names in protected.items():
        old=ast.parse(z.read('asivm/'+file));new=ast.parse(Path(file).read_text())
        for name in names:
            pick=lambda tree:ast.dump(next(n for n in tree.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and n.name==name),include_attributes=False)
            results[file+':'+name]=pick(old)==pick(new)
    old=z.read('asivm/app/static/app.js').decode();new=Path('app/static/app.js').read_text()
    for start,end in [('function loginView()', 'function buildShell()'),('function logout()', 'function loginView()'),('async function boot()', 'boot();')]:
        results[start]=old[old.index(start):old.index(end)]==new[new.index(start):new.index(end)]
print(json.dumps(results,indent=2))
if not all(results.values()):raise SystemExit('Protected scope changed')
