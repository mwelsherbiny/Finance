import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

import pytz
import datetime

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    name = db.execute("SELECT username FROM users WHERE id = ?", session["user_id"])[0][
        "username"
    ]
    cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0][
        "cash"
    ]
    symbols = db.execute("SELECT DISTINCT stock FROM transactions where name = ? ORDER BY price DESC", name)
    stocks = []
    total = cash

    if not db.execute("SELECT * FROM transactions where name = ?", name):
        return render_template("index.html", cash=cash, total=cash, stocks=[])

    for symbol in symbols:
        symbol = symbol["stock"]
        shares = db.execute(
            "SELECT SUM(shares) as total FROM transactions WHERE name = ? AND stock = ? GROUP BY name",
            name,
            symbol,
        )[0]["total"]
        purchased_shares = db.execute(
            "SELECT SUM(shares) as total FROM transactions WHERE name = ? AND stock = ? AND type='purchase' GROUP BY name",
            name,
            symbol,
        )[0]["total"]
        curr_price = lookup(symbol)["price"]
        purchased_total_price = db.execute("SELECT SUM(total) from transactions WHERE name = ? AND stock = ? AND type = 'purchase'", name, symbol)[0]["SUM(total)"]
        curr_total_price = purchased_shares * curr_price
        total_stock = shares * curr_price
        gain_loss_percent = round((curr_total_price - purchased_total_price) / purchased_total_price * 100, 2)
        total += shares * curr_price
        stocks.append(
            {"symbol": symbol, "shares": shares, "curr_price": curr_price, "gain_loss_percent": gain_loss_percent, "total_stock": total_stock}
        )

    return render_template("index.html", cash=cash, total=total, stocks=stocks)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        if not request.form.get("symbol"):
            return apology("symbol is blank")
        if not lookup(request.form.get("symbol")):
            return apology("symbol not found")

        if not request.form.get("shares"):
            return apology("select a number of shares")
        shares = request.form.get("shares")
        if not shares.isdigit():
            return apology("shares can't be fractional")
        shares = int(shares)
        if shares <= 0:
            return apology("shares must be a positive number")

        if not lookup(request.form.get("symbol")):
            return apology("symbol not found")
        symbol = request.form.get("symbol")

        stock = lookup(symbol)
        total = stock["price"] * shares
        user_cash = db.execute(
            "SELECT cash FROM users WHERE id = ?", session["user_id"]
        )

        if float(user_cash[0]["cash"]) < total:
            return apology("not enough cash")

        name = db.execute(
            "SELECT username FROM users WHERE id = ?", session["user_id"]
        )[0]["username"]
        date = datetime.datetime.now(pytz.timezone("US/Eastern"))
        db.execute(
            "INSERT INTO transactions (name, stock, price, shares, total, date, type) VALUES(?, ?, ?, ?, ?, ?, 'purchase')",
            name,
            stock["symbol"],
            stock["price"],
            shares,
            total,
            date,
        )

        updated_cash = user_cash[0]["cash"] - total
        db.execute("UPDATE users SET cash = ? where username = ?", updated_cash, name)

        return redirect("/")

    else:
        return render_template("buy.html")


@app.route("/history", methods=["GET", "POST"])
@login_required
def history():
    """Show history of transactions"""
    if request.method == "POST":
        name = db.execute("SELECT username FROM users WHERE id = ?", session["user_id"])[0][
            "username"
        ]

        if request.form.get("order") == "most-to-least-recent":
            transactions = db.execute(
                "SELECT * FROM transactions WHERE name = ? ORDER BY date DESC", name
            )
            return render_template("history.html", transactions=transactions)

        elif request.form.get("order") == "least-to-most-recent":
            transactions = db.execute(
                "SELECT * FROM transactions WHERE name = ? ORDER BY date ASC", name
            )
            return render_template("history.html", transactions=transactions)

        elif request.form.get("order") == "most-to-least-total":
            transactions = db.execute(
                "SELECT * FROM transactions WHERE name = ? ORDER BY total DESC", name
            )
            return render_template("history.html", transactions=transactions)

        elif request.form.get("order") == "least-to-most-total":
            transactions = db.execute(
                "SELECT * FROM transactions WHERE name = ? ORDER BY total ASC", name
            )
            return render_template("history.html", transactions=transactions)

    else:
        name = db.execute("SELECT username FROM users WHERE id = ?", session["user_id"])[0][
            "username"
        ]
        transactions = db.execute(
            "SELECT * FROM transactions WHERE name = ? ORDER BY date DESC", name
        )

        return render_template("history.html", transactions=transactions)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        if not request.form.get("symbol"):
            return apology("must type symbol")
        symbol = request.form.get("symbol")
        stock = lookup(symbol)
        if not stock:
            return apology("stock not found")
        return render_template("quote.html", stock=stock)

    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure username doesn't already exist
        username = db.execute(
            "SELECT username FROM users where username = ?",
            request.form.get("username"),
        )
        if username:
            return apology("username already exists")

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        # Ensure passwords match
        if request.form.get("password") != request.form.get("confirmation"):
            return apology("passwords don't match", 400)

        # Query database for username
        password = request.form.get("password")
        hash = generate_password_hash(password)
        rows = db.execute(
            "INSERT INTO users (username, hash) VALUES(?, ?)",
            request.form.get("username"),
            hash,
        )

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":
        if not request.form.get("symbol"):
            return apology("select a symbol")
        if not request.form.get("shares"):
            return apology("select a number of shares")
        if (
            not request.form.get("shares").isdigit()
            or int(request.form.get("shares")) < 1
        ):
            return apology("invalid number of shares")

        shares = int(request.form.get("shares"))
        name = db.execute(
            "SELECT username FROM users WHERE id = ?", session["user_id"]
        )[0]["username"]
        symbol = request.form.get("symbol")
        owned_shares = db.execute(
            "SELECT SUM(shares) AS shares from transactions WHERE name = ? AND stock = ?",
            name,
            symbol,
        )[0]["shares"]
        if shares <= 0:
            return apology("shares must be a positive number")
        if shares > owned_shares:
            return apology("not enough shares to sell")

        stock = lookup(symbol)
        total = stock["price"] * float(shares)
        user_cash = db.execute(
            "SELECT cash FROM users WHERE id = ?", session["user_id"]
        )

        date = datetime.datetime.now(pytz.timezone("US/Eastern"))
        db.execute(
            "INSERT INTO transactions (name, stock, price, shares, total, date, type) VALUES(?, ?, ?, ?, ?, ?, 'sell')",
            name,
            stock["symbol"],
            stock["price"],
            -int(shares),
            total,
            date,
        )

        updated_cash = user_cash[0]["cash"] + total
        db.execute("UPDATE users SET cash = ? WHERE username = ?", updated_cash, name)

        return redirect("/")
    else:
        name = db.execute(
            "SELECT username FROM users WHERE id = ?", session["user_id"]
        )[0]["username"]
        symbols = db.execute(
            "SELECT DISTINCT stock FROM transactions where name = ?", name
        )
        print(symbols)

        return render_template("sell.html", symbols=symbols)
