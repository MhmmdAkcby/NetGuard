import pytest
from bs4 import BeautifulSoup
import os

def test_index_html_ui_elements():
    """Verify that the index.html contains the expected UI components for the pentest tab."""
    file_path = os.path.join(os.getcwd(), 'templates', 'index.html')
    with open(file_path, 'r', encoding='utf-8') as f:
        html = f.read()
    
    soup = BeautifulSoup(html, 'html.parser')
    
    # Check for main layout elements
    assert soup.find(id='mainContentArea') is not None
    assert 'overflow-y-auto' in soup.find(id='mainContentArea')['class']
    
    # Check for Pentest View and its elements
    pentest_view = soup.find(id='pentestView')
    assert pentest_view is not None
    assert 'pb-20' in pentest_view['class'] # Ensure scroll space
    
    # Check for Terminal elements
    assert soup.find(id='terminal') is not None
    assert soup.find(id='terminalContainer') is not None
    assert soup.find(id='btnTerminalToggle') is not None
    assert soup.find(id='terminalStatus') is not None
    assert soup.find(id='quickCmdsBar') is not None
    
    # Check for AP Table
    assert soup.find(id='pentestApList') is not None
    
    # Verify Clients table is removed (as requested)
    assert soup.find(id='pentestClientList') is None

def test_app_js_terminal_logic():
    """Basic check to ensure app.js contains terminal initialization logic."""
    file_path = os.path.join(os.getcwd(), 'static', 'app.js')
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    assert 'new Terminal(' in content
    assert 'fitAddon.fit()' in content
    assert 'ws/terminal' in content
    assert 'setTimeout' in content # Ensure sizing fix is present
