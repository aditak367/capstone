from flask import Flask, render_template, jsonify
from browser_extension import BrowserExtension, DataCategory
from datetime import datetime, timedelta

app = Flask(__name__)
extension = BrowserExtension()

@app.route('/')
def dashboard():
    # Test data
    test_url = "https://www.lingscars.com/"
    extension.scan_current_page(test_url)
    extension.record_consent(
        website=test_url,
        data_categories=[DataCategory.BROWSING, DataCategory.BEHAVIORAL],
        purpose="Analytics",
        expiration=datetime.now() + timedelta(days=30)
    )
    
    dashboard_data = extension.get_dashboard_data()
    return render_template('dashboard.html', data=dashboard_data)

if __name__ == '__main__':
    app.run(debug=True)
