const source = document.getElementById("source");
const output = document.getElementById("output");
const status = document.getElementById("status");
const modeEl = document.getElementById("mode");
const modeHint = document.getElementById("modeHint");

function setStatus(text, state) {
    if (!status) return;
    status.textContent = text;
    status.className = state || "";
}

function updateHint() {
    if (!modeHint || !modeEl) return;
    const m = modeEl.value;
    if (m === "hybrid") {
        modeHint.textContent = "mode: hybrid · encrypted payload · loadstring · POST /api/obfuscate";
    } else if (m === "1") {
        modeHint.textContent = "mode: 1-VM · single interpreter · private ISA · POST /api/obfuscate";
    } else {
        modeHint.textContent = "mode: 2-VM · outer+inner nested · private ISA · POST /api/obfuscate";
    }
}

if (modeEl) {
    modeEl.addEventListener("change", updateHint);
    updateHint();
}

if (source) {
    document.getElementById("protectButton").onclick = async () => {
        if (!source.value.trim()) {
            setStatus("Paste source first", "error");
            return;
        }
        const mode = (modeEl && modeEl.value) || "2";
        setStatus("Protecting (" + mode + ")…", "busy");
        try {
            const res = await fetch("/api/obfuscate", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ code: source.value, mode: mode })
            });
            const text = await res.text();
            let data;
            try {
                data = JSON.parse(text);
            } catch {
                throw new Error(text.slice(0, 180) || "Bad server response");
            }
            if (!data.success) throw new Error(data.error || "Protect failed");
            output.value = data.code;
            setStatus("Done [" + (data.mode || mode) + "] — " + data.code.length + " bytes", "done");
        } catch (e) {
            setStatus(String(e.message || e), "error");
        }
    };

    document.getElementById("copyButton").onclick = async () => {
        if (!output.value) return;
        await navigator.clipboard.writeText(output.value);
        setStatus("Copied to clipboard", "done");
    };

    document.getElementById("clearButton").onclick = () => {
        source.value = "";
        output.value = "";
        setStatus("Ready");
    };

    source.addEventListener("keydown", (e) => {
        if (e.key === "Tab") {
            e.preventDefault();
            const start = source.selectionStart;
            const end = source.selectionEnd;
            source.value = source.value.slice(0, start) + "    " + source.value.slice(end);
            source.selectionStart = source.selectionEnd = start + 4;
        }
    });
}