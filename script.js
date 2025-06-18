
let vulnerabilityChartInstance = null;



document.getElementById("scanForm").addEventListener("submit", async function (e) {
    e.preventDefault();
    const mode = document.getElementById("scan-mode").value;

    
    document.getElementById("pro-results").innerHTML = "";
    document.getElementById("chart-container").classList.add("hidden");


    if (mode === "basic") {
        scan();
    } else {
        await runProScan();
    }
});


async function scan() {
    const link = document.getElementById("link-input").value.trim();
    const payloadsRaw = document.getElementById("payload-input").value.trim();
    const scanButton = document.querySelector("#scanForm button[type='submit']");
    
    if (!link) {
        alert("Please enter a URL.");
        return;
    }
    
    if (!payloadsRaw) {
        document.getElementById("payload-notice").style.display = "block";
    } else {
        document.getElementById("payload-notice").style.display = "none";
    }
    
    const payloads = payloadsRaw
    ? payloadsRaw.split("\n").filter(p => p.trim() !== "")
    : ["/admin.php", "/upload.php", "/.env", "/wp-login.php", "/phpinfo.php"];
    const corsProxyUrl = "https://cors-bypasser-gilt.vercel.app/fetchdata";

    const vulnerableElement = document.getElementById("vulnerable-list");
    const notVulnerableElement = document.getElementById("not-vulnerable-list");
    const redirectElement = document.getElementById("redirect-list");

    document.getElementById("vulnerable-count").textContent = 0;
    document.getElementById("not-vulnerable-count").textContent = 0;
    document.getElementById("redirect-count").textContent = 0;
    

    vulnerableElement.innerHTML = "";
    notVulnerableElement.innerHTML = "";
    redirectElement.innerHTML = "";

    scanButton.disabled = true;
    scanButton.textContent = "Scanning...";
    document.getElementById("loading").classList.remove("hidden");
    document.getElementById("summary-results").style.display = "none";
    
    let vulnerableCount = 0, notVulnerableCount = 0, redirectCount = 0;

    for (const payload of payloads) {
        const completeUrl = link + payload.trim();
        const fetchUrl = `${corsProxyUrl}?url=${encodeURIComponent(completeUrl)}`;

        try {
            const response = await fetch(fetchUrl, { method: "HEAD" });
            const status = response.status;

            if (status >= 200 && status < 300) {
                vulnerableElement.innerHTML += `${completeUrl}<br>`;
                vulnerableCount++;
            } else if (status >= 300 && status < 400) {
                redirectElement.innerHTML += `${completeUrl}<br>`;
                redirectCount++;
            } else {
                notVulnerableElement.innerHTML += `${completeUrl}<br>`;
                notVulnerableCount++;
            }
        } catch (error) {
            notVulnerableElement.innerHTML += `${completeUrl} (Error)<br>`;
            notVulnerableCount++;
        }

        document.getElementById("vulnerable-count").textContent = vulnerableCount;
        document.getElementById("not-vulnerable-count").textContent = notVulnerableCount;
        document.getElementById("redirect-count").textContent = redirectCount;
    }


    scanButton.disabled = false;
    
    document.getElementById("total-tested").textContent = payloads.length;
    document.getElementById("summary-results").style.display = "block";
    document.getElementById("loading").classList.add("hidden");

    scanButton.textContent = "SCAN";
}

async function runProScan() {
    const url = document.getElementById("link-input").value.trim();
    const loader = document.getElementById("loading");
    const resultBlock = document.getElementById("pro-results");

    loader.classList.remove("hidden");
    resultBlock.innerHTML = "";

    try {
        const res = await fetch("http://localhost:8000/scan", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url })
        });

        const data = await res.json();
        
        
        if (data && data.length > 0) {
            renderVulnerabilityChart(data); 
            displayProResults(data); 
        } else {
             resultBlock.innerHTML = "<p>✅ No vulnerabilities found.</p>";
        }
        

    } catch (err) {
        resultBlock.innerHTML = "<p style='color: red;'>Error while contacting backend. Make sure the Python server is running.</p>";
    } finally {
        loader.classList.add("hidden");
    }
}


function displayProResults(data) {
    const resultBlock = document.getElementById("pro-results");
    let html = "<h3>Pro Scan Results</h3><table border='1' style='width:100%;color:white;text-align:left;'>";
    html += "<tr><th>Name</th><th>Severity</th><th>Description</th><th>Recommendation</th></tr>";

    for (let vuln of data) {
        html += `<tr>
                    <td>${vuln.name}</td>
                    <td style="color: ${getSeverityColor(vuln.severity)};">${vuln.severity}</td>
                    <td>${vuln.description}</td>
                    <td>${vuln.recommendation}</td>
                </tr>`;
    }

    html += "</table>";
    html += "<br><a href='http://localhost:8000/report' target='_blank'><button>📥 Download Full HTML Report</button></a>";
    resultBlock.innerHTML = html;
}



function renderVulnerabilityChart(data) {
    const chartContainer = document.getElementById("chart-container");
    if (!data || data.length === 0) {
        chartContainer.classList.add("hidden");
        return;
    }

    
    const severityCounts = {
        'High': 0,
        'Medium': 0,
        'Low': 0
    };

    data.forEach(vuln => {
        if (severityCounts.hasOwnProperty(vuln.severity)) {
            severityCounts[vuln.severity]++;
        }
    });

    
    if (vulnerabilityChartInstance) {
        vulnerabilityChartInstance.destroy();
    }

    
    const ctx = document.getElementById('vulnerabilityChart').getContext('2d');
    vulnerabilityChartInstance = new Chart(ctx, {
        type: 'doughnut', 
        data: {
            labels: ['High Severity', 'Medium Severity', 'Low Severity'],
            datasets: [{
                label: 'Vulnerabilities Found',
                data: [severityCounts.High, severityCounts.Medium, severityCounts.Low],
                backgroundColor: [
                    'rgba(255, 87, 87, 0.8)',  
                    'rgba(255, 165, 0, 0.8)', 
                    'rgba(25, 175, 25, 0.8)'    
                ],
                borderColor: [
                    'rgba(255, 87, 87, 1)',
                    'rgba(255, 165, 0, 1)',
                    'rgba(25, 175, 25, 1)'
                ],
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: 'top',
                    labels: {
                        color: 'white' 
                    }
                },
                title: {
                    display: true,
                    text: 'Vulnerability Distribution',
                    color: 'white' 
                }
            }
        }
    });
    
   
    chartContainer.classList.remove("hidden");
}

function getSeverityColor(severity) {
    switch (severity) {
        case 'High': return '#ff5757';
        case 'Medium': return '#ffa500';
        case 'Low': return '#19af19';
        default: return 'white';
    }
}




async function loadScanHistory() {
    const container = document.getElementById("history-list");
    try {
      const res = await fetch("http://localhost:8000/history");
      const history = await res.json();
  
      if (history.length === 0) {
        container.innerHTML = "<p>No scans yet.</p>";
        return;
      }
  
      let html = "<table border='1' style='width:100%;color:white;text-align:left;'>";
      html += "<tr><th>Time</th><th>URL</th><th>Vulns Found</th><th>Report</th></tr>";
      history.forEach(entry => {
        html += `<tr>
          <td>${entry.timestamp}</td>
          <td>${entry.url}</td>
          <td>${entry.vulnerability_count}</td>
          <td><a href="http://localhost:8000/report" target="_blank">📄 Download </a></td>
        </tr>`;
      });
      html += "</table>";
      container.innerHTML = html;
  
    } catch (err) {
      container.innerHTML = "<p style='color:red;'>Failed to load history.</p>";
    }
}
  
async function clearHistory() {
    if (!confirm("Are you sure you want to delete all scan history?")) return;
  
    try {
      const res = await fetch("http://localhost:8000/history/clear", {
        method: "DELETE"
      });
  
      const data = await res.json();
      alert(data.status);
      
      loadScanHistory();
  
    } catch (err) {
      alert("Error.");
    }
}



document.getElementById("payload-file").addEventListener("change", function(event) {
    const file = event.target.files[0];
    if (file && file.type === "text/plain") {
        const reader = new FileReader();
        reader.onload = function(e) {
            const text = e.target.result;
            document.getElementById("payload-input").value = text.trim();
        };
        reader.readAsText(file);
    } else {
        alert("Please upload a valid .txt file.");
    }
});



loadScanHistory();