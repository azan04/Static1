# app_pickle.py
from flask import Flask, request, jsonify
import pickle
import base64
import os

app = Flask(__name__)

class UserProfile:
    """A simple class to demonstrate object deserialization."""
    def __init__(self, username, is_admin=False):
        self.username = username
        self.is_admin = is_admin

    def __str__(self):
        return f"User(username='{self.username}', admin={self.is_admin})"

@app.route('/load_profile', methods=['POST'])
def load_profile():
    """
    Loads a user profile from a Base64 encoded pickle string.
    This is INSECURE.
    """
    try:
        data = request.json
        if 'profile_data' not in data:
            return jsonify({"error": "No profile_data provided"}), 400

        # --- VULNERABILITY ---
        # Unsafely deserializing data from a user.
        # A static analysis tool will flag 'pickle.loads' as dangerous.
        decoded_data = base64.b64decode(data['profile_data'])
        profile = pickle.loads(decoded_data) 
        # --- END VULNERABILITY ---

        print(f"Loaded profile: {profile}")
        return jsonify({
            "status": "success",
            "username": profile.username,
            "is_admin": profile.is_admin
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    print("Starting insecure pickle server...")
    # Static analysis will also flag debug=True
    app.run(debug=True, port=5001)
