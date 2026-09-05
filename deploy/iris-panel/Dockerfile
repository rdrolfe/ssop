# SSOP Decision Panel — derived IRIS app image.
#
# This deployment runs the PREBUILT ghcr.io/dfir-iris/iriswebapp_app image
# (no `build:` key in the compose files — the host ~/iris-web/source tree is
# never mounted into the container, so editing it alone can never activate
# the panel). This Dockerfile layers the panel ON TOP of the stock image:
# durable across container recreation, and rebuildable against a newer base
# tag when IRIS is upgraded.
#
# Select it in ~/iris-web/.env:  APP_IMAGE_NAME=iriswebapp_app
#                                APP_IMAGE_TAG=ssop-panel
# then `docker compose up -d app worker`.
#
# Build: docker build -t iriswebapp_app:ssop-panel <this dir>
FROM ghcr.io/dfir-iris/iriswebapp_app:v2.4.29

# New panel files (blueprint + template).
COPY case_ssop_routes.py /iriswebapp/app/blueprints/case/case_ssop_routes.py
COPY templates/case_ssop.html /iriswebapp/app/blueprints/case/templates/case_ssop.html

# Phase 2: case-list SSOP columns (overrides the stock datatable + template).
COPY manage.cases.js /iriswebapp/app/static/assets/js/iris/manage.cases.js
COPY manage_cases.html /iriswebapp/app/blueprints/manage/templates/manage_cases.html

# Wire the blueprint import/registration + the nav tab into the stock files.
# Anchored + idempotent: fails loudly if a stock anchor vanished (so an
# upstream bump can't silently produce a panel-less image), skips if the
# patch is already applied.
RUN python3 - <<'PYEOF'
from pathlib import Path

routes = Path('/iriswebapp/app/blueprints/case/case_routes.py')
s = routes.read_text()
if 'case_ssop' not in s:
    imp = 'from app.blueprints.case.case_timeline_routes import case_timeline_blueprint\n'
    assert imp in s, 'import anchor missing from case_routes.py'
    s = s.replace(imp, imp + 'from app.blueprints.case.case_ssop_routes import case_ssop_blueprint\n', 1)
    reg = 'app.register_blueprint(case_tasks_blueprint)\n'
    assert reg in s, 'register anchor missing from case_routes.py'
    s = s.replace(reg, reg + 'app.register_blueprint(case_ssop_blueprint)\n', 1)
    routes.write_text(s)
    print('case_routes.py patched')
else:
    print('case_routes.py already patched')

nav = Path('/iriswebapp/app/blueprints/case/templates/case-nav.html')
n = nav.read_text()
if 'case_ssop' not in n:
    tab = ('            <li class="nav-item">\n'
           '                <a class="nav-link" href="/case/ssop?cid={{session[\'current_case\'].case_id}}">\n'
           '                    <span class="menu-title">SSOP</span>\n'
           '                </a>\n'
           '            </li>\n')
    idx = n.rfind('</ul>')
    assert idx > 0, 'nav </ul> anchor missing from case-nav.html'
    nav.write_text(n[:idx] + tab + n[idx:])
    print('case-nav.html patched')
else:
    print('case-nav.html already patched')

# --- Phase 2: expose custom_attributes on case create so the SSOP summary
# (decision/engine/playbook/agent) can ride into the case list UI. ---
schema = Path('/iriswebapp/app/schema/marshables.py')
m = schema.read_text()
if '    custom_attributes: Optional[Dict[str, Any]]' not in m:
    anchor = "    severity_id: Optional[int] = auto_field('severity_id', required=False, allow_none=True)\n"
    assert anchor in m, 'CaseSchema severity_id anchor missing'
    field = anchor + "    custom_attributes: Optional[Dict[str, Any]] = auto_field('custom_attributes', required=False)\n"
    m = m.replace(anchor, field, 1)
    schema.write_text(m)
    print('CaseSchema custom_attributes added')
else:
    print('CaseSchema already patched')
PYEOF
