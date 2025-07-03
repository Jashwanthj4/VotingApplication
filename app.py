from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect
from bson.objectid import ObjectId
from datetime import datetime
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "your_default_secret_key")
csrf = CSRFProtect(app)


# MongoDB Atlas setup
# client = MongoClient(os.getenv("MONGO_URI"))
client = MongoClient("mongodb://Voter_System:mongodbroot@cluster1-shard-00-00.3noeutm.mongodb.net:27017,cluster1-shard-00-01.3noeutm.mongodb.net:27017,cluster1-shard-00-02.3noeutm.mongodb.net:27017/?ssl=true&replicaSet=atlas-abc-shard-0&authSource=admin&retryWrites=true&w=majority")

db = client["voting_system"]
userscol = db["users"]
candidatescol = db["candidates"]
votescol = db["votes"]
activity_logscol = db["activity_logs"]  # For logging user actions

# -------------------- Routes --------------------

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role')
        
        if userscol.find_one({'email': email}):
            flash("Email already registered.")
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)
        userscol.insert_one({'name': name, 'email': email, 'password': hashed_password, 'role': role})
        log_activity(email, f"Registered as {role}")
        flash("Registration successful! Please login.")
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = userscol.find_one({'email': email})
        if user and check_password_hash(user['password'], password):
            session['email'] = user['email']
            session['role'] = user['role']
            log_activity(email, "Logged in")
            return redirect(url_for('admin_dashboard' if user['role'] == 'admin' else 'voter_dashboard'))
        flash("Invalid credentials.")
    return render_template('login.html')

@app.route('/logout')
def logout():
    log_activity(session.get('email'), "Logged out")
    session.clear()
    return redirect(url_for('login'))

# ------------------ Admin Routes ------------------

@app.route('/admin/dashboard')
def admin_dashboard():
    if session.get('role') != 'admin':
        return redirect(url_for('login'))
    all_candidates = list(candidatescol.find())
    voters = list(votescol.find({'role': 'voter'}))
    return render_template('admin_dashboard.html', candidates=all_candidates, voters=voters)

@app.route('/admin/add-candidate', methods=['GET', 'POST'])
def add_candidate():
    if session.get('role') != 'admin':
        return redirect(url_for('login'))
    if request.method == 'POST':
        name = request.form.get('name')
        position = request.form.get('position')
        candidatescol.insert_one({'name': name, 'position': position})
        log_activity(session['email'], f"Added candidate: {name}")
        flash("Candidate added.")
        return redirect(url_for('admin_dashboard'))
    return render_template('add_candidate.html')

@app.route('/admin/view-voters')
def view_voters():
    if session.get('role') != 'admin':
        return redirect(url_for('login'))
    voters = list(userscol.find({'role': 'voter'}))
    voted_emails = [v['voter_email'] for v in votescol.find()]
    return render_template('view_voters.html', voters=voters, voted_emails=voted_emails)

# ------------------ Voter Routes ------------------

@app.route('/voter/dashboard')
def voter_dashboard():
    if session.get('role') != 'voter':
        return redirect(url_for('login'))
    has_voted = votescol.find_one({'voter_email': session['email']})
    return render_template('voter_dashboard.html', has_voted=has_voted is not None)

@app.route('/voter/cast-vote', methods=['GET', 'POST'])
def cast_vote():
    if session.get('role') != 'voter':
        return redirect(url_for('login'))
    if request.method == 'POST':
        candidate_id = request.form.get('candidate_id')
        if votescol.find_one({'voter_email': session['email']}):
            flash("You have already voted!")
            return redirect(url_for('voter_dashboard'))
        votescol.insert_one({'voter_email': session['email'], 'candidate_id': ObjectId(candidate_id), 'time': datetime.utcnow()})
        log_activity(session['email'], f"Voted for candidate ID: {candidate_id}")
        flash("Your vote has been recorded.")
        return redirect(url_for('voter_dashboard'))
    candidate_list = list(candidatescol.find())
    return render_template('cast_vote.html', candidates=candidate_list)

@app.route('/voter/voting-status')
def voting_status():
    vote = votescol.find_one({'voter_email': session['email']})
    candidate = candidatescol.find_one({'_id': vote['candidate_id']}) if vote else None
    return render_template('voting_status.html', vote=vote, candidate=candidate)

# ------------------ Results ------------------

@app.route('/results')
def view_results():
    pipeline = [
        {"$group": {"_id": "$candidate_id", "vote_count": {"$sum": 1}}},
        {"$sort": {"vote_count": -1}}
    ]
    results = list(votescol.aggregate(pipeline))
    for r in results:
        candidate = candidatescol.find_one({'_id': r['_id']})
        r['name'] = candidate['name']
        r['position'] = candidate['position']
    return render_template('view_results.html', results=results)

# ------------------ REST API ------------------

@app.route('/api/candidates', methods=['GET'])
def api_get_candidates():
    all_candidates = list(candidatescol.find())
    for c in all_candidates:
        c['_id'] = str(c['_id'])
    return jsonify(all_candidates)

@app.route('/api/vote', methods=['POST'])
def api_vote():
    data = request.get_json()
    email = data.get('email')
    candidate_id = data.get('candidate_id')
    if not email or not candidate_id:
        return jsonify({"error": "Email and candidate_id are required"}), 400
    if votescol.find_one({'voter_email': email}):
        return jsonify({"message": "Already voted"}), 403
    votescol.insert_one({'voter_email': email, 'candidate_id': ObjectId(candidate_id), 'time': datetime.utcnow()})
    log_activity(email, f"API vote for candidate {candidate_id}")
    return jsonify({"message": "Vote recorded"}), 201

@app.route('/api/results', methods=['GET'])
def api_results():
    pipeline = [
        {"$group": {"_id": "$candidate_id", "votes": {"$sum": 1}}},
        {"$sort": {"votes": -1}}
    ]
    results = list(votescol.aggregate(pipeline))
    for r in results:
        candidate = candidatescol.find_one({"_id": r["_id"]})
        r["_id"] = str(r["_id"])
        r["name"] = candidate["name"]
        r["position"] = candidate["position"]
    return jsonify(results)

# ------------------ Utilities ------------------

def log_activity(email, action):
    activity_logscol.insert_one({
        'email': email,
        'action': action,
        'timestamp': datetime.utcnow()
    })

# ------------------ Run App ------------------

if __name__ == '__main__':
    app.run(debug=True)
