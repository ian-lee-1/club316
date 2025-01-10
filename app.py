import os
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from helpers import apology, login_required

app = Flask(__name__)

app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

db = SQL("sqlite:///club.db")


@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    events = db.execute("SELECT name, description, date, time, location FROM events ORDER BY date ASC, time ASC")
    return render_template("index.html", events=events)


@app.route("/login", methods=["GET", "POST"])
def login():
    session.clear()
    if request.method == "POST":
        if not request.form.get("username"):
            return apology("must provide username", 400)
        if not request.form.get("password"):
            return apology("must provide password", 400)

        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 400)

        session["user_id"] = rows[0]["id"]
        return redirect("/")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():
    session.clear()
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        password2 = request.form.get("confirmation")

        if not username:
            flash("Must provide username.", "danger")
            return redirect("/register")
        if not password:
            flash("Must provide password.", "danger")
            return redirect("/register")
        if password != password2:
            flash("Passwords do not match.", "danger")
            return redirect("/register")

        hash = generate_password_hash(password)
        try:
            db.execute(
                "INSERT INTO users (username, hash) VALUES (:u, :h)", u=username, h=hash
            )
        except ValueError:
            flash("Username already exists.", "warning")
            return redirect("/register")

        flash("Registered successfully! Please log in.", "success")
        return redirect("/login")

    return render_template("register.html")


@app.route("/host", methods=["GET", "POST"])
@login_required
def host():
    if request.method == "POST":
        name = request.form.get("name")
        description = request.form.get("description")
        date = request.form.get("date")
        time = request.form.get("time")
        location = request.form.get("location")

        if not name or not description or not date or not time or not location:
            flash("All fields are required.", "danger")
            return redirect("/host")

        db.execute("INSERT INTO events (host_id, name, description, date, time, location) VALUES (?, ?, ?, ?, ?, ?)",
                   session["user_id"], name, description, date, time, location)

        flash("Event hosted successfully!", "success")
        return redirect("/events")

    return render_template("host_event.html")


@app.route("/events")
@login_required
def events():
    events = db.execute("""
        SELECT event_id, name, description, date, time, location, host_id AS creator_id
        FROM events
        ORDER BY date ASC, time ASC
    """)
    return render_template("events.html", events=events)


@app.route("/rsvp", methods=["POST"])
@login_required
def rsvp():
    event_id = request.form.get("event_id")

    if not event_id:
        flash("Event ID is required.", "danger")
        return redirect("/events")

    existing_rsvp = db.execute(
        "SELECT * FROM rsvps WHERE user_id = ? AND event_id = ?",
        session["user_id"], event_id
    )

    if existing_rsvp:
        flash("You have already RSVP'd to this event.", "warning")
        return redirect("/events")

    db.execute(
        "INSERT INTO rsvps (user_id, event_id) VALUES (?, ?)",
        session["user_id"], event_id
    )

    flash("RSVP successful!", "success")
    return redirect("/dashboard")


@app.route("/opt_out", methods=["POST"])
@login_required
def opt_out():
    event_id = request.form.get("event_id")

    if not event_id:
        flash("Event ID is required to opt out.", "danger")
        return redirect("/dashboard")

    db.execute(
        "DELETE FROM rsvps WHERE user_id = ? AND event_id = ?",
        session["user_id"], event_id
    )

    flash("Successfully opted out of the event.", "success")
    return redirect("/dashboard")


@app.route("/dashboard")
@login_required
def dashboard():
    """Show RSVP'd events for the user"""
    events = db.execute("""
        SELECT events.event_id, events.name, events.description, events.date, events.time, events.location
        FROM rsvps
        JOIN events ON rsvps.event_id = events.event_id
        WHERE rsvps.user_id = ?
        ORDER BY events.date ASC, events.time ASC
    """, session["user_id"])  # Ensure this passes the session["user_id"]
    return render_template("dashboard.html", events=events)


@app.route("/cancel_event", methods=["POST"])
@login_required
def cancel_event():
    event_id = request.form.get("event_id")
    if not event_id:
        flash("Event ID is required.", "danger")
        return redirect("/events")

    # Ensure the user is the creator of the event
    event = db.execute("SELECT * FROM events WHERE event_id = ? AND host_id = ?", event_id, session["user_id"])
    if not event:
        flash("You do not have permission to cancel this event.", "danger")
        return redirect("/events")

    # Delete associated RSVPs first
    db.execute("DELETE FROM rsvps WHERE event_id = ?", event_id)

    # Now delete the event
    db.execute("DELETE FROM events WHERE event_id = ?", event_id)

    flash("Event canceled successfully.", "success")
    return redirect("/events")
