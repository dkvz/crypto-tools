require('./styles/styles.pcss')
// Make sure the favicon is part of the bundle:
require('../assets/favicon.ico')

import * as Crypto from './crypto'

const warnClass = 'text-yellow-500'

//TODO
// I should probably create some kind of abstraction
// for the "multimodule" approach of the page.

const [
  cryptForm,
  clearBtn,
  encryptRadio,
  loadingModal,
  msg,
  payloadText,
  passwordInput,
  // Certificate decoder:
  certForm,
  msgCert,
  certText,
  certClearBtn,
  certInfoSection
] = [
  'cryptForm',
  'clearBtn',
  'encryptRadio',
  'loadingModal',
  'msg',
  'payloadText',
  'passwordInput',
  // Certificate decoder:
  'certForm',
  'msgCert',
  'certText',
  'certClearBtn',
  'certInfoSection'
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

function showMsg(message, warning = true, msgEl = msg) {
  if (message) {
    msgEl.textContent = message
    warning && msgEl.classList.add(warnClass)
    msgEl.classList.remove('hidden')
    msgEl.scrollIntoView()
  } else {
    clearMsg()
  }
}

function clearMsg(msgEl = msg) {
  msgEl.classList.add('hidden')
  msgEl.classList.remove(warnClass)
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
    showMsg(`Error: ${ex.message}`)
  } finally {
    displayLoading(false)
  }
})

certForm.addEventListener('submit', async (e) => {
  
})

clearBtn.addEventListener('click', () => {
  clearMsg()
  passwordInput.value = ''
  payloadText.innerText = ''
})

certClearBtn.addEventListener('click', () => {
  clearMsg(msgCert)
  certText.innerText = ''
  certInfoSection.classList.add('hidden')
})

// TODO Hide certInfoSection if certText is empty.