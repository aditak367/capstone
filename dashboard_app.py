from flask import Flask, render_template, jsonify, request
from website import Website

app = Flask(__name__)
extension = Website()

@app.route('/')
def dashboard():
    dashboard_data = extension.get_dashboard_data()
    return render_template('dashboard.html', data=dashboard_data)

@app.route('/scan', methods=['POST'])
def scan_website():
    url = request.json.get('url')
    if not url:
        return jsonify({'error': 'No URL provided'}), 400
    
    try:
        website_data = extension.scan_current_page(url)
        if website_data:
            trackers = [{
                'name': t.name,
                'category': t.category.value,
                'risk_level': t.risk_level,
                'description': t.description,
                'data_collected': list(t.data_collected),
                'is_essential': t.is_essential,
                'has_consent': t.has_consent
            } for t in website_data.trackers]

            return jsonify({
                'url': website_data.url,
                'trackers': trackers,
                'privacy_score': {
                    'score': website_data.privacy_score,
                    'explanation': website_data.privacy_explanation
                },
                'risk_score': {
                    'score': website_data.risk_score,
                    'explanation': website_data.risk_explanation
                },
                'scan_time': website_data.scan_time.isoformat()
            })
        else:
            return jsonify({'error': 'Failed to scan website'}), 500
    except Exception as e:
        print(f"Scan error: {str(e)}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
