const port = process.env.PORT || "3000"

const express = require("express")

const app = express()

const w3id = require(`${__dirname}/../index`)

app.set("port", port)

app.get("/logout", (req, res) => {
	const oneWeekInMilliseconds = 604800000

	res.cookie("w3id_challenge", 1, { httpOnly: false, maxAge: oneWeekInMilliseconds })
	res.end()
})

app.get("/", (req, res) => {
	res.end()
})

app.use(w3id)

app.get("/protected", (req, res) => {
	res.end()
})

module.exports = app
