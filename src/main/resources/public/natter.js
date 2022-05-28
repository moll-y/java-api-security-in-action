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

const apiUrl = 'https://localhost:4567'

function createSpace(name, owner) {
  const data = { name, owner }
  fetch(apiUrl + '/spaces', {
    method: 'POST',
    credentials: 'include',
    body: JSON.stringify(data),
    headers: {
      'Content-Type': 'application/json'
    }
  }).then(res => {
    if (res.ok) {
      return res.json()
    } else {
      throw Error(res.statusText)
    }
  }).then(json => console.log('Created space: ', json.name, json.uri))
    .catch(err => console.error('Error: ', err))
}
