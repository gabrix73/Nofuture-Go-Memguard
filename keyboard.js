/*******************************************************
 * keyboard.js (VERSIONE SENZA encryptInBackground)
 *
 * - Mostra/Nasconde la tastiera virtuale
 * - Inserisce caratteri in chiaro dentro #textInput
 * - Nessuna logica di cifratura/offuscamento
 ******************************************************/

document.addEventListener("DOMContentLoaded", () => {
  const showKeyboardButton  = document.getElementById("showKeyboardButton");
  const keyboardTooltip     = document.getElementById("keyboardTooltip");
  const keyboardContainer   = document.getElementById("keyboardContainer");
  const closeKeyboardButton = document.getElementById("closeKeyboardButton");
  const virtualKeyboard     = document.getElementById("virtualKeyboard");
  const keyboardHeader      = document.getElementById("keyboardHeader");

  // Campo di testo dove inserire i caratteri
  const textInput           = document.getElementById("textInput");

  // Layout fisso per la tastiera (nessun random, nessuna cifratura)
  const layout = [
    "q","w","e","r","t","y","u","i","o","p",
    "a","s","d","f","g","h","j","k","l","_",
    "z","x","c","v","b","n","m","0","1","2",
    "3","4","5","6","7","8","9",".","-","@"
  ];

  /*******************************************************
   * Tooltip su pulsante “Virtual Keyboard”
   *******************************************************/
  showKeyboardButton.addEventListener("mouseenter", () => {
    keyboardTooltip.style.display = "block";
    const btnRect = showKeyboardButton.getBoundingClientRect();
    // Posiziona tooltip SOPRA il pulsante
    keyboardTooltip.style.left = btnRect.left + "px";
    keyboardTooltip.style.top  = (btnRect.top - keyboardTooltip.offsetHeight - 8) + "px";
  });
  showKeyboardButton.addEventListener("mouseleave", () => {
    keyboardTooltip.style.display = "none";
  });

  /*******************************************************
   * Mostra/Nasconde #keyboardContainer
   *******************************************************/
  showKeyboardButton.addEventListener("click", () => {
    keyboardContainer.style.display = "block"; // Mostra la tastiera
    generateKeyboard(); // Crea i tasti
  });

  closeKeyboardButton.addEventListener("click", () => {
    keyboardContainer.style.display = "none"; // Nasconde la tastiera
  });

  /*******************************************************
   * Genera i tasti della tastiera virtuale
   *******************************************************/
  function generateKeyboard() {
    virtualKeyboard.innerHTML = ""; // Pulisce il contenuto precedente

    // Crea i tasti per ogni carattere del layout
    layout.forEach(char => {
      const keyElem = document.createElement("div");
      keyElem.classList.add("key");
      keyElem.textContent = char;
      // Al click sul tasto, aggiunge il char al textInput in chiaro
      keyElem.addEventListener("click", () => {
        if (textInput) {
          textInput.value += char;
        }
      });
      virtualKeyboard.appendChild(keyElem);
    });

    // Aggiunge tasti speciali (Space, Backspace, Clear)
    addSpecialKeys();
  }

  function addSpecialKeys() {
    // [space]
    const spaceKey = document.createElement("div");
    spaceKey.classList.add("key");
    spaceKey.textContent = "[space]";
    spaceKey.addEventListener("click", () => {
      if (textInput) {
        textInput.value += " ";
      }
    });
    virtualKeyboard.appendChild(spaceKey);

    // Backspace
    const backspaceKey = document.createElement("div");
    backspaceKey.classList.add("key");
    backspaceKey.textContent = "Backspace";
    backspaceKey.addEventListener("click", () => {
      if (textInput && textInput.value.length > 0) {
        textInput.value = textInput.value.slice(0, -1);
      }
    });
    virtualKeyboard.appendChild(backspaceKey);

    // Clear
    const clearKey = document.createElement("div");
    clearKey.classList.add("key");
    clearKey.textContent = "Clear";
    clearKey.addEventListener("click", () => {
      if (textInput) {
        textInput.value = "";
      }
    });
    virtualKeyboard.appendChild(clearKey);
  }

  /*******************************************************
   * Drag & Drop della tastiera
   *******************************************************/
  let isDragging = false;
  let offsetX = 0, offsetY = 0;

  keyboardHeader.addEventListener("mousedown", (e) => {
    isDragging = true;
    offsetX = e.clientX - keyboardContainer.offsetLeft;
    offsetY = e.clientY - keyboardContainer.offsetTop;
  });

  document.addEventListener("mousemove", (e) => {
    if (isDragging) {
      keyboardContainer.style.left = (e.clientX - offsetX) + "px";
      keyboardContainer.style.top  = (e.clientY - offsetY) + "px";
    }
  });

  document.addEventListener("mouseup", () => {
    isDragging = false;
  });
});
