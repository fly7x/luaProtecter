const source = document.getElementById("source");
const output = document.getElementById("output");
const status = document.getElementById("status");

function setStatus(text, state) {
    status.textContent = text;
    status.className = state || "";
}

if (source) {
    document.getElementById("protectButton").onclick = async () => {
        if (!source.value.trim()) { setStatus("Paste source first", "error"); return; }
        setStatus("Protecting…", "busy");
        try {
            const res = await fetch("/api/obfuscate", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ code: source.value, vm: "true", polymorphic: "true" })
            });
            const text = await res.text();
            let data;
            try { data = JSON.parse(text); }
            catch { throw new Error(text.slice(0, 180) || "Bad server response"); }
            if (!data.success) throw new Error(data.error || "Protect failed");
            output.value = data.code;
            setStatus("Done — " + data.code.length + " bytes", "done");
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
            const start = source.selectionStart, end = source.selectionEnd;
            source.value = source.value.slice(0, start) + "    " + source.value.slice(end);
            source.selectionStart = source.selectionEnd = start + 4;
        }
    });
}
