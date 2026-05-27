from __future__ import annotations

from flask import Blueprint, current_app, jsonify, render_template, request, send_from_directory

from app.extensions import limiter
from app.forms import URLForm
from app.models import Analysis, Feedback, db
from .heuristics import AnalysisInputError
from .services import filtered_reports, recent_analyses, run_analysis, serialize_analysis

bp = Blueprint('phishing', __name__)


@bp.route('/')
def index():
    return render_template('index.html', form=URLForm(), recent=recent_analyses(), page_title='Analyze suspicious websites')


@bp.route('/result/<int:analysis_id>')
def result_detail(analysis_id: int):
    analysis = Analysis.query.get_or_404(analysis_id)
    return render_template('result.html', analysis=analysis, serialized=serialize_analysis(analysis), page_title='Analysis result')


@bp.route('/offline')
def offline():
    return render_template('offline.html', page_title='Offline')


@bp.route('/manifest.json')
def manifest():
    return send_from_directory(current_app.static_folder, 'manifest.json', mimetype='application/manifest+json')


@bp.route('/sw.js')
def service_worker():
    response = send_from_directory(current_app.static_folder, 'sw.js', mimetype='application/javascript')
    response.headers['Service-Worker-Allowed'] = '/'
    response.headers['Cache-Control'] = 'no-cache'
    return response


@bp.route('/api/analyze', methods=['POST'])
@limiter.limit(lambda: current_app.config['ANALYZE_RATE_LIMIT'])
def api_analyze():
    payload = request.get_json(silent=True) or {}
    url = (payload.get('url') or '').strip()
    try:
        result = run_analysis(url, current_app.config)
    except AnalysisInputError as exc:
        current_app.logger.warning('invalid_analysis_input', extra={'path': request.path, 'method': request.method})
        return jsonify({'error': {'type': exc.error_type, 'message': exc.message}}), 400
    analysis = Analysis.query.get(result.analysis_id)
    return jsonify(serialize_analysis(analysis))


@bp.route('/api/reports')
@limiter.limit(lambda: current_app.config['REPORTS_RATE_LIMIT'])
def api_reports():
    pagination = filtered_reports(
        page=max(int(request.args.get('page', 1)), 1),
        per_page=min(max(int(request.args.get('per_page', 20)), 1), 100),
        label=request.args.get('label') or None,
        domain=request.args.get('domain') or None,
        date_from=request.args.get('date_from') or None,
        date_to=request.args.get('date_to') or None,
    )
    return jsonify(
        {
            'items': [serialize_analysis(item) for item in pagination.items],
            'pagination': {
                'page': pagination.page,
                'pages': pagination.pages,
                'per_page': pagination.per_page,
                'total': pagination.total,
            },
        }
    )


@bp.route('/api/export/json')
@limiter.limit(lambda: current_app.config['REPORTS_RATE_LIMIT'])
def api_export_json():
    pagination = filtered_reports(
        page=1,
        per_page=min(max(int(request.args.get('per_page', 100)), 1), 500),
        label=request.args.get('label') or None,
        domain=request.args.get('domain') or None,
        date_from=request.args.get('date_from') or None,
        date_to=request.args.get('date_to') or None,
    )
    return jsonify({'items': [serialize_analysis(item) for item in pagination.items]})


@bp.route('/feedback/<int:analysis_id>', methods=['POST'])
def feedback(analysis_id: int):
    analysis = Analysis.query.get_or_404(analysis_id)
    db.session.add(Feedback(analysis_id=analysis.id))
    db.session.commit()
    return jsonify({'status': 'recorded'})


@bp.route('/disclaimer')
def disclaimer():
    return render_template('disclaimer.html', page_title='Disclaimer')


@bp.route('/privacy')
def privacy():
    return render_template('privacy.html', page_title='Privacy')


@bp.route('/terms')
def terms():
    return render_template('terms.html', page_title='Terms')
