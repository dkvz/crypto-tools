require('./styles/styles.pcss')

const [cryptForm, clearBtn, encryptRadio, loadingModal] = [
  'cryptForm', 'clearBtn', 'encryptRadio', 'loadingModal'
].map(e => document.getElementById(e))

function displayLoading(show) {
  if (show) {
    document.body.setAttribute('data-overlay', true)
    scrollTo(0, 0);
    loadingModal.classList.remove('hidden')
  } else {
    document.body.removeAttribute('data-overlay')
    loadingModal.classList.add('hidden')
  }
}

cryptForm.addEventListener('submit', (e) => {
  e.preventDefault()
  displayLoading(true)
})