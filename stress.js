// stressTest.js
const fetch = require("node-fetch");
const fs = require("fs");
const path = require("path");

const BASE_URL = "http://16.176.180.114:3000"; // EC2
const USERNAME = "admin";
const PASSWORD = "admin";

// Files to upload
const videoFiles = [
    // path.join(__dirname, "videouploads", "sample1 - large.mp4"),
    path.join(__dirname, "videouploads", "sample2 - small.mp4")
];

const TOTAL_REQUESTS = 10;       // total transcoding requests
const MAX_CONCURRENT = 2;       // maximum concurrent jobs
const TRANSCODE_RESOLUTION = "1280x720";
const FORMAT = "avi";
const TIMEOUT_MS = 6 * 60 * 1000; // 5 minutes

function log(msg) {
    const timestamp = new Date().toISOString();
    console.log(`[${timestamp}] ${msg}`);
}

async function login() {
    const res = await fetch(`${BASE_URL}/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: USERNAME, password: PASSWORD })
    });
    const data = await res.json();
    if (!data.token) throw new Error("Login failed");
    return data.token;
}

async function uploadVideo(token, filePath) {
    const fileStream = fs.createReadStream(filePath);
    const form = new (require("form-data"))();
    form.append("video", fileStream);

    const res = await fetch(`${BASE_URL}/upload`, {
        method: "POST",
        headers: { "Authorization": `Bearer ${token}` },
        body: form
    });

    const data = await res.json();
    log(`Uploaded ${data.filename}`);
    return data.filename;
}

async function transcodeVideo(token, filename) {
    const res = await fetch(`${BASE_URL}/transcode`, {
        method: "POST",
        headers: {
            "Authorization": `Bearer ${token}`,
            "Content-Type": "application/json"
        },
        body: JSON.stringify({ filename, format: FORMAT, resolution: TRANSCODE_RESOLUTION })
    });
    const data = await res.json();
    log(`Transcoded ${filename}: ${data.output}`);
    return data;
}

// Limited concurrency runner
async function runLimitedConcurrency(tasks, maxConcurrent, timeoutMs) {
    const results = [];
    let index = 0;
    let stop = false;

    const timeout = setTimeout(() => {
        log("TIMEOUT reached! Aborting remaining tasks...");
        stop = true;
    }, timeoutMs);

    async function worker() {
        while (!stop && index < tasks.length) {
            const i = index++;
            try {
                results[i] = await tasks[i]();
            } catch (err) {
                log(`Error in task ${i}: ${err.message}`);
            }
        }
    }

    const workers = [];
    for (let i = 0; i < maxConcurrent; i++) {
        workers.push(worker());
    }

    await Promise.all(workers);
    clearTimeout(timeout);
    return results;
}

async function stressTest() {
    const token = await login();

    // Upload all files
    const uploadedFiles = await Promise.all(videoFiles.map(file => uploadVideo(token, file)));

    // Prepare 6 transcoding tasks
    const tasks = [];
    for (let i = 0; i < TOTAL_REQUESTS; i++) {
        const file = uploadedFiles[i % uploadedFiles.length];
        tasks.push(() => transcodeVideo(token, file));
    }

    log(`Starting ${TOTAL_REQUESTS} transcoding requests with max ${MAX_CONCURRENT} concurrently...`);
    await runLimitedConcurrency(tasks, MAX_CONCURRENT, TIMEOUT_MS);
    log("Stress test complete!");
}

stressTest().catch(err => console.error("Error:", err));
