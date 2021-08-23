require('./styles/styles.pcss')

const warnClass = 'text-yellow-500'

const [
  cryptForm,
  clearBtn,
  encryptRadio,
  loadingModal,
  msg,
  payloadText,
  passwordInput
] = [
  'cryptForm',
  'clearBtn',
  'encryptRadio',
  'loadingModal',
  'msg',
  'payloadText',
  'passwordInput'
].map(e => document.getElementById(e))

function displayLoading(show) {
  if (show) {
    document.body.setAttribute('data-overlay', true)
    scrollTo(0, 0)
    loadingModal.classList.remove('hidden')
  } else {
    document.body.removeAttribute('data-overlay')
    loadingModal.classList.add('hidden')
  }
}

function showMsg(message, warning = true) {
  if (message) {
    msg.textContent = message
    warning && msg.classList.add(warnClass)
    msg.classList.remove('hidden')
    msg.scrollIntoView()
  } else {
    clearMsg()
  }
}

function clearMsg() {
  msg.classList.add('hidden')
  msg.classList.remove(warnClass)
}

cryptForm.addEventListener('submit', (e) => {
  e.preventDefault()
  displayLoading(true)
  clearMsg()

})