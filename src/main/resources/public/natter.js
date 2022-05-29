const apiUrl = 'https://localhost:4567'

window.addEventListener('load', function(_) {
  document.getElementById('createSpace').addEventListener('submit', processFormSubmit);
})

function processFormSubmit(e) {
  e.preventDefault()

  const spaceName = document.getElementById('spaceName').value
  const owner = document.getElementById('owner').value

  createSpace(spaceName, owner)
  return false;
}

function createSpace(name, owner) {
  const data = { name, owner }
  const csrfToken = getCookie('csrfToken')
  console.log('crsfToken: ', csrfToken)

  fetch(apiUrl + '/spaces', {
    method: 'POST',
    credentials: 'include',
    body: JSON.stringify(data),
    headers: {
      'Content-Type': 'application/json',
      'X-CSRF-Token': csrfToken
    }
  }).then(res => {
    if (res.ok) {
      return res.json()
    } else if (res.status === 401) {
      window.location.replace('/login.html')
    } else {
      throw Error(res.statusText)
    }
  }).then(json => console.log('Created space: ', json.name, json.uri))
    .catch(err => console.error('Error: ', err))
}

function getCookie(cookieName) {
  const cookieValue = document.cookie.split(';')
    .map(item => item.split('=').map(x => decodeURIComponent(x.trim())))
    .filter(item => item[0] === cookieName)[0]

  if (cookieValue) {
    return cookieValue[1]
  }
}
