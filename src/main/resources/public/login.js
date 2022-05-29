const apiUrl = 'https://localhost:4567'

window.addEventListener('load', function(_) {
  document.getElementById('login').addEventListener('submit', processLoginSubmit);
})

function processLoginSubmit(e) {
  e.preventDefault()

  const username = document.getElementById('username').value
  const password = document.getElementById('password').value

  login(username, password)
  return false;
}

function login(username, password) {
  // Encode the credentials for basic authentication.
  const credentials = 'Basic ' + btoa(username + ':' + password);
  fetch(apiUrl + '/sessions', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': credentials
    }
  }).then(res => {
    if (res.ok) {
      // If successful, then set the csrfToken cookie and redirect to the
      // Natter UI.
      res.json().then(json => {
        document.cookie = 'csrfToken=' + json.token + ';Secure;SameSite=strict'
        window.location.replace('/natter.html')
      })
    }
  }).catch(err => console.log('Error logging in: ', err))
}
