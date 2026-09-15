// Inasoma maandishi (kutoka .txt, .docx, .pdf, au OCR ya picha) na kutoa orodha ya maswali
// Muundo unaotambuliwa:
// Q: <swali>
// A) <chaguo>
// B) <chaguo>
// C) <chaguo>
// D) <chaguo>
// ANSWER: <herufi A-D> au TRUE/FALSE
//
// Kila swali linatenganishwa na mstari mtupu au swali linalofuata la "Q:"

function parseQuestionsFromText(text) {
  const lines = text.replace(/\r\n/g, '\n').split('\n').map(l => l.trim());
  const questions = [];
  let current = null;

  function pushCurrent() {
    if (!current || !current.questionText) return;
    if (current.answerRaw) {
      const ans = current.answerRaw.trim().toUpperCase();
      if (ans === 'TRUE' || ans === 'KWELI') {
        current.type = 'true_false';
        current.correctAnswer = 'Kweli';
        current.options = [];
      } else if (ans === 'FALSE' || ans === 'SIKWELI') {
        current.type = 'true_false';
        current.correctAnswer = 'Sikweli';
        current.options = [];
      } else if (/^[A-D]$/.test(ans) && current.options.length) {
        const idx = ans.charCodeAt(0) - 65;
        current.type = 'mcq';
        current.correctAnswer = current.options[idx] || '';
      } else {
        current.type = current.options.length ? 'mcq' : 'true_false';
        current.correctAnswer = current.answerRaw.trim();
      }
    }
    if (current.questionText && current.correctAnswer) {
      questions.push({
        type: current.type || (current.options.length ? 'mcq' : 'true_false'),
        questionText: current.questionText,
        options: current.options,
        correctAnswer: current.correctAnswer,
        marks: 1
      });
    }
    current = null;
  }

  for (const raw of lines) {
    const line = raw;
    if (/^Q[:.]\s*/i.test(line)) {
      pushCurrent();
      current = { questionText: line.replace(/^Q[:.]\s*/i, '').trim(), options: [], answerRaw: null };
    } else if (current && /^[A-D]\)\s*/.test(line)) {
      current.options.push(line.replace(/^[A-D]\)\s*/, '').trim());
    } else if (current && /^ANSWER[:.]\s*/i.test(line)) {
      current.answerRaw = line.replace(/^ANSWER[:.]\s*/i, '').trim();
    } else if (line === '' ) {
      // mstari mtupu - kama swali lina jibu tayari, funga
      if (current && current.answerRaw) pushCurrent();
    }
  }
  pushCurrent();
  return questions;
}

module.exports = { parseQuestionsFromText };
