document.getElementById('searchInput').addEventListener('input', function (e) {
  const searchTerm = e.target.value.trim().toLowerCase();
  const allCards = document.querySelectorAll('.log-card, .logon-type-card');

  allCards.forEach(card => {
    removeHighlights(card);

    if (searchTerm.length < 1) {
      card.style.display = 'block';
      return;
    }

    const text = card.textContent.toLowerCase();

    if (text.includes(searchTerm)) {
      card.style.display = 'block';
      const elements = card.querySelectorAll('h3, p, span');

      elements.forEach(el => {
        [...el.childNodes].forEach(node => {
          if (node.nodeType === Node.TEXT_NODE) {
            const lowerText = node.nodeValue.toLowerCase();
            const matchIndex = lowerText.indexOf(searchTerm);
            if (matchIndex !== -1) {
              const originalText = node.nodeValue;
              const before = document.createTextNode(originalText.slice(0, matchIndex));
              const match = document.createElement('span');
              match.className = 'search-highlight';
              match.textContent = originalText.slice(matchIndex, matchIndex + searchTerm.length);
              const after = document.createTextNode(originalText.slice(matchIndex + searchTerm.length));
              el.replaceChild(after, node);
              el.insertBefore(match, after);
              el.insertBefore(before, match);
            }
          }
        });
      });
    } else {
      card.style.display = 'none';
    }
  });
});

function removeHighlights(container) {
  const highlights = container.querySelectorAll('span.search-highlight');
  highlights.forEach(span => {
    const parent = span.parentNode;
    parent.replaceChild(document.createTextNode(span.textContent), span);
    parent.normalize(); // merges adjacent text nodes
  });
}
