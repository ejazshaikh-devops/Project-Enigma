<h1>GuardAI (Project Enigma) — Technical Overview</h1>
<h2>Project Type</h2>
<br>
Browser-based AI-assisted phishing and scam detection platform.
Current implementation is a Chrome Extension prototype built using Manifest V3 architecture. The project is designed to evolve into a full cybersecurity platform with browser protection, threat intelligence collection, analytics, and AI-driven phishing detection.

<h2>Current Development Stage</h2>
<br>
<h3>Prototype Status</h3>
<br>
Early-stage working prototype.

<br>
<h3>Approximate maturity</h3>
<br>
* Prototype readiness: 3/10
<br>
* Production readiness: 1.5/10
<br>
* Architecture quality: moderate
<br>
* Scalability readiness: low but expandable
<br>

<h3>The current version demonstrates</h3>
<br>
* live browser monitoring
<br>
* phishing heuristic detection
<br>
* suspicious form detection
<br>
* extension-based architecture
<br>
* modular frontend logic
<br>

<h3>The project is not production-ready yet and currently lacks</h3>

* backend infrastructure
* ML threat intelligence
* telemetry pipelines
* cloud analytics
* large-scale threat databases
* real-world validation metrics

<h2>High-Level Vision</h2>

<h3>The long-term objective of GuardAI is to become</h3>

<h4>An AI-powered browser security platform focused on phishing prevention, scam detection, suspicious website analysis, and localized cybersecurity intelligence for Indian internet users.
Future architecture will include</h4>
<br>
* browser extension
<br>
* backend threat intelligence platform
<br>
* machine learning pipeline
<br>
* live analytics dashboard
<br>
* real-time malicious domain database
<br>
* crowdsourced threat reporting
<br>
* enterprise APIs
<br>

<h2>Current Technology Stack</h2>
<h3></h3>Frontend / Extension</
* JavaScript
<br>
* HTML
<br>
* CSS
<br>
* Chrome Extension APIs
<br>
* Manifest V3
<br>

<h3>Planned Backend</h3>

* FastAPI (Python)
  <br>
* PostgreSQL
  <br>
* Redis
  <br>
* Docker
  <brt>
* Nginx
  <br>
  
<h3>Planned ML Stack</h3>
* Python
<br>
* Scikit-learn
<br>
* XGBoost
<br>
* Pandas
<br>
* NumPy

<h2>Current Project Structure</h2>

    guardai-final/
    │
    ├── extension/
    │   
    │   ├── background/
    │   │   └── worker.js
    │   │
    │   ├── content/
    │   │   ├── detector.js
    │   │   └── formWatcher.js
    │   │
    │   ├── popup/
    │   │   ├── popup.html
    │   │   └── popup.js
    │   │
    │   ├── icons/
    │   │
    │   └── manifest.json
    │
    └── README / supporting files

<h3>Architecture Explanation</h3>
<h4>1. manifest.json</h4>
<br>
Purpose: Defines the Chrome extension configuration.
<br>

<h4>Responsibilities</h4>
* permissions
<br>
* content script injection
<br>
* background worker registration
<br>
* popup registration
<br>
* extension metadata
<br>
* security policies
<br>
<h5>Current Role: Acts as the central configuration entry point for the extension.</h5>

<h3>2. Background Layer</h3>
<h4>File</h4>
<br>
background/worker.js
<br>
Purpose: Runs as the extension’s persistent background service worker.
<h4></h4>Responsibilities:

* event handling
  <br>
* extension lifecycle management
  <br>
* communication handling
  <br>
* future telemetry syncing
  <br.
* future API communication
  <br.
<h5>Current Status: Basic event architecture exists but requires refactoring for scalability and security.</h5>

<h3>3. Content Scripts</h3>
<br>
detector.js
<br>
Purpose: Primary phishing and scam detection logic.
<h4></h4>Responsibilities

* page inspection
  <br>
* suspicious URL checks
  <br>
* phishing heuristics
  <br>
* content analysis
  <br>
* risk evaluation
  <br.
<h5>Current Detection Approach: Mostly heuristic-based.</h5>
<h5></h5>Examples:

* suspicious keywords
* login form analysis
* URL structure checks
* deceptive page patterns
  
<h6>Limitations</h6>

* no machine learning
* no live threat feeds
* no external reputation lookup
* limited contextual intelligence

<h5>formWatcher.js</h5>
Purpose: Monitors webpage forms for suspicious behavior.
<h6></h6>Responsibilities:

* password form observation
* hidden field detection
* risky input behavior analysis
* credential collection indicators
<h5>Importance: This module is critical because phishing attacks commonly target credential forms.<h5></h5>

<h3>4. Popup UI</h3>
popup.html
Purpose: Frontend UI shown when user clicks the extension icon.
<h4></h4>Displays:

* extension status
* threat detection summaries
* risk notifications
* future analytics

<h4>popup.js<h4></h4>
Purpose: Controls popup interactions and UI logic.
<h4></h4>Responsibilities:
  
* render detection data
* communicate with background worker
* display warning states
* future telemetry summaries

<h2>Current Detection Workflow<h2></h2>

    User opens website
             ↓
    Content scripts inject into page
             ↓
    detector.js scans:
          - URL
          - forms
          - suspicious patterns
             ↓
    Risk score generated
             ↓
    Popup UI displays result
             ↓
    Future:
    Threat sent to backend analytics

<h2>Current Strengths<h2></h2>
  
1. Real Working Prototype
The extension is operational and not just conceptual.
<br>
  
2. Correct Base Architecture
Manifest V3 and modular content/background separation were chosen correctly.
<br>

3. Security-Oriented Design Direction
The project already focuses on:

* phishing prevention
* suspicious form monitoring
* browser-level protection

4. Expandable Foundation
The current structure can evolve into:

* AI-based detection
* cloud analytics
* enterprise threat intelligence

<h2>Current Weaknesses</h2>

1. No Backend
No centralized threat intelligence or telemetry currently exists.

2. No ML Detection
Detection is heuristic-only and cannot provide measurable AI accuracy yet.

3. No Data Pipeline
No real phishing datasets integrated.

4. No Threat Intelligence Layer
No malicious domain feeds or reputation systems yet.

5. No User Analytics
No installs, telemetry, or detection metrics exist yet.

<h2>Planned Future Architecture<h2></h2>

    Chrome Extension
        ↓
    FastAPI Backend
        ↓
    Threat Intelligence Engine
        ↓
    ML Detection System
        ↓
    Analytics Dashboard
        ↓
    Threat Database

<h1>Planned Core Features</h1>
<h2></h2>Browser Protection

* phishing detection
* scam prevention
* malicious form monitoring
  
<h3>AI Detection</h3>

* phishing classification
* suspicious language analysis
* behavioral threat analysis

<h3></h3>Threat Intelligence

* malicious domain database
* crowdsourced reporting
* live threat feeds

<h3>Analytics</h3>

* detection statistics
* active threats
* attack heatmaps
* telemetry dashboards

<h1>Development Philosophy</h1>
<h2></h2>The project is intentionally being developed in phases:

1. stable architecture
2. reliable detection
3. backend infrastructure
4. ML integration
5. analytics
6. production deployment
7. investor readiness

<h3>The focus is on</h3>

* engineering quality
* scalability
* measurable security performance
* real-world usability
<h4></h4>rather than rapidly shipping incomplete features.
