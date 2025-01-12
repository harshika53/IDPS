# notification_blueprint.py

from flask import Blueprint, request, jsonify
from backend.services.notifier import send_notification  # Ensure this path is correct

# Create the blueprint
notification_Blueprint = Blueprint('notify', __name__)

@notification_Blueprint.route('/notify', methods=['POST'])
def notify():
    data = request.get_json()
    message = data.get('message')
    
    if not message:
        return jsonify({"error": "Message is required"}), 400

    # Call the send_notification function
    send_notification(message)
    return jsonify({"status": "Notification sent"})
