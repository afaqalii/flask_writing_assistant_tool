document.addEventListener("DOMContentLoaded", function() {
    console.log("DOM fully loaded and parsed");

    const createProjectBtn = document.getElementById('create-project-btn');
    const startKeywordGenerationBtn = document.getElementById('start-keyword-generation-btn');
    const keywordGenerationForm = document.getElementById('keyword-generation-form');
    const generateSuggestionsBtn = document.getElementById('generate-suggestions-btn');
    const goToTextEditorBtn = document.getElementById('go-to-text-editor-btn');

    createProjectBtn.addEventListener('click', function() {
        document.getElementById('main-page').style.display = 'none';
        document.getElementById('new-project-page').style.display = 'block';
    });

    startKeywordGenerationBtn.addEventListener('click', function() {
        const projectName = document.getElementById('project-name').value;
        if (projectName) {
            const projects = JSON.parse(localStorage.getItem('projects')) || [];
            projects.push({ name: projectName, keywords: {} });
            localStorage.setItem('projects', JSON.stringify(projects));
            document.getElementById('new-project-page').style.display = 'none';
            document.getElementById('keyword-generation-page').style.display = 'block';
        } else {
            alert('Please enter a project name');
        }
    });

    keywordGenerationForm.addEventListener('submit', function(event) {
        event.preventDefault();
        const focusKeyword = document.getElementById('focus-keyword').value;
        if (focusKeyword) {
            fetch('/writingassistant/api/generate_keywords/', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': getCookie('csrftoken')
                },
                body: JSON.stringify({ content: focusKeyword })
            })
            .then(response => response.json())
            .then(data => {
                if (data.error) {
                    alert('Error: ' + data.error);
                } else {
                    const keywordsOutput = document.getElementById('keywords-output');
                    const targetKeywords = document.getElementById('target-keywords');
                    const recommendedKeywords = document.getElementById('recommended-keywords');

                    keywordsOutput.innerHTML = `
                        <h3>Generated Keywords</h3>
                        <h4>Content:</h4>
                        <p>${data.content}</p>
                        <h4>Long Tail Keywords:</h4>
                        <ul>${data.long_tail_keywords.map(kw => `<li>${kw}</li>`).join('')}</ul>
                        <h4>LSI Keywords:</h4>
                        <ul>${data.lsi_keywords.map(kw => `<li>${kw}</li>`).join('')}</ul>
                    `;

                    targetKeywords.innerHTML = data.long_tail_keywords.map(kw => `<li>${kw}</li>`).join('');
                    recommendedKeywords.innerHTML = data.lsi_keywords.map(kw => `<div>${kw}</div>`).join('');

                    goToTextEditorBtn.style.display = 'block';
                }
            })
            .catch(error => {
                console.error("Error generating keywords:", error);
            });
        } else {
            alert('Please enter a focus keyword');
        }
    });

    generateSuggestionsBtn.addEventListener('click', function() {
        const editorContent = window.editor.getData();
        fetch('/writingassistant/api/generate_suggestions/', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': getCookie('csrftoken')
            },
            body: JSON.stringify({ content: editorContent })
        })
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                alert('Error: ' + data.error);
            } else {
                const suggestionsOutput = document.getElementById('suggestions-output');
                suggestionsOutput.innerHTML = data.suggestions.map(suggestion => `<li>${suggestion}</li>`).join('');
            }
        })
        .catch(error => {
            console.error("Error generating suggestions:", error);
        });
    });

    goToTextEditorBtn.addEventListener('click', function() {
        document.getElementById('keyword-generation-page').style.display = 'none';
        document.getElementById('text-editor-page').style.display = 'block';
        initializeEditor();
    });

    function getCookie(name) {
        let cookieValue = null;
        if (document.cookie && document.cookie !== '') {
            const cookies = document.cookie.split(';');
            for (let i = 0; i < cookies.length; i++) {
                const cookie = cookies[i].trim();
                if (cookie.substring(0, name.length + 1) === (name + '=')) {
                    cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                    break;
                }
            }
        }
        return cookieValue;
    }

    function initializeEditor() {
        ClassicEditor
            .create(document.querySelector('#editor'))
            .then(editor => {
                window.editor = editor;
                console.log("CKEditor initialized");
            })
            .catch(error => {
                console.error("Error initializing CKEditor:", error);
            });
    }
});
