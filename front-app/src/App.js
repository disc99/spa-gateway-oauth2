import React, { Component } from 'react'
import './App.css'

const authorizationUrl = 'http://localhost:9999/uaa'
const gatewayUrl = 'http://localhost:8080'
const clientId = 'demo'

class App extends Component {

  constructor(props) {
    super(props)
    this.state = {
      isSessionExpire: false,
      name: null,
      result: null
    }
    this.checkToken = this.checkToken.bind(this)
    this.userinfo = this.userinfo.bind(this)
    this.profile = this.profile.bind(this)
    this.httpGet = this.httpGet.bind(this)
    this.paramsFromHash = this.paramsFromHash.bind(this)
    this.handleClick = this.handleClick.bind(this)
  }

  componentDidMount() {
    this.paramsFromHash(window.location.hash)
    if (!this.checkToken(window.location)) {
        return
    }

    this.userinfo()
        .then((user) => this.setState({name: user.name}))
  }

  paramsFromHash(hash) {
    hash = hash.charAt(0) === '#' ? hash.substring(1) : hash
    const regex = /([^&=]+)=([^&]*)/g
    let m
    while ((m = regex.exec(hash)) !== null) {
        localStorage.setItem(decodeURIComponent(m[1]), decodeURIComponent(m[2]))
    }
  }

  checkToken(location) {
    if (!(localStorage.getItem('access_token'))) {
      // redirect
      window.location.href = authorizationUrl + '/oauth/authorize?client_id=' + clientId + '&response_type=token&redirect_uri=' + location.href
      return false
    } else {
      // Remove hash
      location.hash = ''
      return true
    }
  }

  userinfo() {
    return this.httpGet(authorizationUrl + '/userinfo')
  }

  profile() {
    return this.httpGet(gatewayUrl + '?property=helpers.contextualCard')
  }

  httpGet(url) {
    return fetch(url, {
      method: 'GET',
      headers:{
        'Authorization': 'Bearer ' + localStorage.getItem('access_token'),
        'Accept': 'application/json'
      }
    }).then(res => {
        if (res.status === 401) {
            localStorage.removeItem('access_token')
            this.setState({isSessionExpire: true})
            throw new Error(res.statusText)
        }
        return res.json()
    }).catch(err => {
        console.error(err)
    })
  }

  handleClick() {
    this.profile()
        .then(json => this.setState({result: JSON.stringify(json)}))
  }

  render() {
    return (
      <div className="App">
        <div style={{display: this.state.isSessionExpire ? 'block' : 'none'}}>The session has expired. Please reload the page.</div>
        <div>Hello {this.state.name}</div>
        <button onClick={this.handleClick}>Load Profile</button>
        <div>{this.state.result}</div>
      </div>
    )
  }
}

export default App
