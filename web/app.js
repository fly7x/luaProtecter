const source = document.getElementById("source");
const output = document.getElementById("output");
const status = document.getElementById("status");

document.getElementById("protectButton").onclick = async () => {
    const code = source.value;
    if (!code.trim()) {
        status.textContent = "Paste source first";
        return;
    }
    status.textContent = "Protecting...";
    try {
        const res = await fetch("/api/obfuscate", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ code: code, vm: "true", polymorphic: "true" })
        });
        const text = await res.text();
        let data;
        try { data = JSON.parse(text); }
        catch { throw new Error(text.slice(0, 180) || "Bad server response"); }
        if (!data.success) throw new Error(data.error || "Protect failed");
        output.value = data.code;
        status.textContent = "Done (" + data.code.length + " bytes)";
    } catch (e) {
        status.textContent = String(e.message || e);
    }
};

document.getElementById("copyButton").onclick = async () => {
    if (!output.value) return;
    await navigator.clipboard.writeText(output.value);
    status.textContent = "Copied";
};

document.getElementById("clearButton").onclick = () => {
    source.value = "";
    output.value = "";
    status.textContent = "Ready";
};