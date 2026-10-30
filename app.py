import streamlit as st
import pandas as pd
import plotly.graph_objects as go
from datetime import datetime
from url_analyzer import analyze_url
from message_analyzer import analyze_message
from fuzzy_engine import assess_risk
from database import init_db, save_analysis, get_history, clear_history

st.set_page_config(page_title="PhishGuard AI", page_icon="🛡️", layout="wide")
init_db()

st.markdown("""
<style>
.main {background-color:#f7f9fc;}
.block-container {padding-top:1.6rem; padding-bottom:2rem;}
.hero {padding:1.4rem 1.6rem; border-radius:16px; background:linear-gradient(120deg,#0f172a,#134e4a); color:white; margin-bottom:1rem;}
.hero h1 {color:white; margin-bottom:.25rem;}
.hero p {color:#dbeafe; margin-bottom:0;}
.small-note {color:#64748b; font-size:.9rem;}
</style>
""", unsafe_allow_html=True)

with st.sidebar:
    st.title("🛡️ PhishGuard AI")
    page = st.radio("Navigation", ["Analyse", "Analysis History", "Statistics", "About"])
    st.divider()
    st.caption("An educational phishing-risk assessment tool.")
    st.caption("Do not open suspicious links or enter real passwords/OTPs.")

if page == "Analyse":
    st.markdown('<div class="hero"><h1>PhishGuard AI</h1><p>Explainable phishing risk assessment using fuzzy logic.</p></div>', unsafe_allow_html=True)
    st.write("Check a suspicious link or message for common warning signs. The tool analyses the text you provide; it does not visit the URL.")
    mode = st.radio("What would you like to analyse?", ["Message or email", "URL"], horizontal=True)
    if mode == "Message or email":
        sample = st.selectbox("Try an example", ["Choose an example", "Suspicious message", "Ordinary message"])
        examples = {
            "Suspicious message": "URGENT: Your bank account will be suspended today. Verify your account and send your OTP immediately: http://secure-bank-login.example.com/verify",
            "Ordinary message": "Hi, our study group meeting is at 4 PM in the library. Please bring your notes."
        }
        default_text = examples.get(sample, "")
        user_text = st.text_area("Paste the message or email text", value=default_text, height=180, placeholder="Paste the message here. Do not include real passwords or OTPs.")
        submitted = st.button("Analyse message", type="primary", use_container_width=True)
        if submitted:
            if not user_text.strip():
                st.warning("Please enter a message to analyse.")
            else:
                features = analyze_message(user_text)
                result = assess_risk(features)
                warnings = features["warnings"]
                save_analysis("Message", user_text, result["score"], result["category"], warnings)
                st.session_state["latest"] = {"type":"Message", "text":user_text, "features":features, "result":result}
    else:
        sample = st.selectbox("Try an example URL", ["Choose an example", "Suspicious example", "Ordinary example"])
        examples = {
            "Suspicious example": "http://192.0.2.10/login/verify-account?session=123456789",
            "Ordinary example": "https://www.example.com/about"
        }
        url_text = st.text_input("Paste a URL (it will not be opened)", value=examples.get(sample, ""), placeholder="https://example.com")
        submitted = st.button("Analyse URL", type="primary", use_container_width=True)
        if submitted:
            if not url_text.strip():
                st.warning("Please enter a URL.")
            else:
                features = analyze_url(url_text)
                result = assess_risk(features)
                save_analysis("URL", url_text, result["score"], result["category"], features["warnings"])
                st.session_state["latest"] = {"type":"URL", "text":url_text, "features":features, "result":result}

    latest = st.session_state.get("latest")
    if latest:
        st.divider()
        result = latest["result"]
        features = latest["features"]
        score = result["score"]
        col1, col2 = st.columns([1, 1.7])
        with col1:
            color = "#16a34a" if score < 25 else "#ca8a04" if score < 50 else "#ea580c" if score < 75 else "#dc2626"
            fig = go.Figure(go.Indicator(
                mode="gauge+number", value=score, number={"suffix":"/100"},
                title={"text":"Estimated phishing risk"},
                gauge={"axis":{"range":[0,100]}, "bar":{"color":color},
                       "steps":[{"range":[0,25],"color":"#dcfce7"},{"range":[25,50],"color":"#fef9c3"},
                                {"range":[50,75],"color":"#ffedd5"},{"range":[75,100],"color":"#fee2e2"}],
                       "threshold":{"line":{"color":"#111827","width":3},"thickness":0.8,"value":score}}
            ))
            fig.update_layout(height=280, margin=dict(l=15,r=15,t=55,b=10))
            st.plotly_chart(fig, use_container_width=True)
            st.subheader(f"Verdict: {result['category']}")
            st.write(result["summary"])
        with col2:
            st.subheader("Warning signs")
            if features["warnings"]:
                for warning in features["warnings"]:
                    st.markdown(f"- ⚠️ {warning}")
            else:
                st.success("No configured warning signs were detected. This does not guarantee that the content is safe.")
            st.subheader("Signals used by the fuzzy system")
            signal_df = pd.DataFrame([
                {"Signal":"URL suspicion", "Value":features["url_suspicion"]},
                {"Signal":"Urgency", "Value":features["urgency"]},
                {"Signal":"Sensitive-data request", "Value":features["sensitive_request"]},
                {"Signal":"Deceptive language", "Value":features["deception"]},
            ])
            st.bar_chart(signal_df.set_index("Signal"))
            st.caption("Signal values are heuristic inputs on a 0–100 scale; the final score is produced by the fuzzy inference engine.")
        with st.expander("How was this result calculated?"):
            st.write("The application maps the extracted signals to fuzzy membership values, evaluates Mamdani-style IF–THEN rules, aggregates the rule outputs, and uses centroid defuzzification to produce the score.")
            st.json({k:v for k,v in features.items() if k != "warnings"})
            st.caption("This is a prototype, not a security guarantee. Legitimate messages can trigger warnings and sophisticated phishing can evade these checks.")

elif page == "Analysis History":
    st.title("Analysis History")
    st.write("Recent analyses saved locally in the project's SQLite database.")
    history = get_history()
    if history.empty:
        st.info("No analyses yet. Run an analysis from the Analyse page.")
    else:
        st.dataframe(history.drop(columns=["content"], errors="ignore"), use_container_width=True, hide_index=True)
        with st.expander("View stored input text"):
            st.dataframe(history[["timestamp","input_type","content","risk_score","verdict"]], use_container_width=True, hide_index=True)
        if st.button("Clear all history", type="secondary"):
            clear_history()
            st.success("History cleared.")
            st.rerun()

elif page == "Statistics":
    st.title("Statistics Dashboard")
    history = get_history()
    if history.empty:
        st.info("Statistics will appear after you analyse some messages or URLs.")
    else:
        c1,c2,c3 = st.columns(3)
        c1.metric("Total analyses", len(history))
        c2.metric("High or critical", int(history["risk_score"].ge(50).sum()))
        c3.metric("Average risk score", f"{history['risk_score'].mean():.1f}/100")
        left,right = st.columns(2)
        with left:
            counts = history["verdict"].value_counts().rename_axis("Risk category").reset_index(name="Count")
            st.subheader("Risk category distribution")
            st.bar_chart(counts.set_index("Risk category"))
        with right:
            daily = history.copy()
            daily["date"] = pd.to_datetime(daily["timestamp"], errors="coerce").dt.date
            trend = daily.groupby("date", as_index=False)["risk_score"].mean()
            st.subheader("Average risk over time")
            st.line_chart(trend.set_index("date"))
        st.caption("Statistics reflect only analyses stored on this computer, not global phishing prevalence.")

else:
    st.title("About PhishGuard AI")
    st.markdown("""
### Project overview
PhishGuard AI is an educational web application that assesses the risk of phishing-style URLs and messages using transparent heuristics and a fuzzy inference system.

### Intelligent Systems concepts
- Fuzzification and membership functions
- Fuzzy IF–THEN rules
- Mamdani-style inference
- Aggregation and centroid defuzzification
- Reasoning under uncertainty

### Safety and privacy
- Submitted URLs are analysed as text and are **not opened or fetched**.
- Analysis history is stored locally in `phishguard.db`.
- Do not paste real passwords, OTPs, account numbers, or confidential messages.
- The score is a risk indicator, not a definitive classification or guarantee of safety.

### Limitations
The current version uses transparent rules rather than a trained phishing dataset. It does not check live domain reputation, certificate details, redirects, or website content. Some legitimate content may be flagged, and some phishing attempts may not be detected.
""")
