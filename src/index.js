require('./styles/styles.pcss')

import * as Crypto from './crypto'

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

cryptForm.addEventListener('submit', async (e) => {
  e.preventDefault()
  displayLoading(true)
  clearMsg()
  try {
    if (payloadText.innerText.length <= 0)
      throw new Error('There is no text to process')

    if (!passwordInput.value)
      throw new Error('Please enter a passphrase')

    if (encryptRadio.checked) {
      payloadText.innerText = await Crypto.encrypt(
        payloadText.innerText,
        passwordInput.value
      )
    } else {
      payloadText.innerText = await Crypto.decrypt(
        payloadText.innerText,
        passwordInput.value
      )
    }
    passwordInput.value = ''

  } catch (ex) {
    console.log(ex)
    showMsg(ex.message)
  } finally {
    displayLoading(false)
  }
})