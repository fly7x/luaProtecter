const source = document.getElementById("source");
const output = document.getElementById("output");
const protectButton = document.getElementById("protectButton");
const clearButton = document.getElementById("clearButton");
const copyButton = document.getElementById("copyButton");
const buttonText = document.getElementById("buttonText");
const spinner = document.getElementById("spinner");
const outputStatus = document.getElementById("outputStatus");
const rename = document.getElementById("rename");
const strings = document.getElementById("strings");
const constants = document.getElementById("constants");
const controlFlow = document.getElementById("controlFlow");
const deadCode = document.getElementById("deadCode");
const vmMode = document.getElementById("vmMode");

clearButton.addEventListener("click", () => {
    source.value = "";
    output.value = "";
    outputStatus.textContent = "Nothing generated yet";
});

copyButton.addEventListener("click", async () => {
    if (!output.value) return;
    try {
        await navigator.clipboard.writeText(output.value);
        copyButton.textContent = "Copied";
        setTimeout(() => { copyButton.textContent = "Copy"; }, 1200);
    } catch {
        output.select();
        document.execCommand("copy");
        copyButton.textContent = "Copied";
        setTimeout(() => { copyButton.textContent = "Copy"; }, 1200);
    }
});

protectButton.addEventListener("click", async () => {
    const code = source.value;
    if (!code.trim()) {
        outputStatus.textContent = "Paste Luau code first";
        source.focus();
        return;
    }
    
    protectButton.disabled = true;
    buttonText.classList.add("hidden");
    spinner.classList.remove("hidden");
    outputStatus.textContent = "Protecting source...";
    
    try {
        const response = await fetch("/api/obfuscate", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                code: code,
                options: {
                    rename: rename.checked,
                    strings: strings.checked,
                    constants: constants.checked,
                    controlFlow: controlFlow.checked,
                    deadCode: deadCode.checked,
                    vm: vmMode.checked
                }
            })
        });
        
        const data = await response.json();
        if (!response.ok || !data.success) {
            throw new Error(data.error || "Obfuscation failed");
        }
        output.value = data.code || "";
        outputStatus.textContent = "Protection complete";
    } catch (error) {
        output.value = "";
        outputStatus.textContent = error.message || "Request failed";
    } finally {
        protectButton.disabled = false;
        buttonText.classList.remove("hidden");
        spinner.classList.add("hidden");
    }
});