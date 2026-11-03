#!/usr/bin/env node
// One-time Uptime Kuma v2 provisioning through an SSH-forwarded loopback port.
// Depends only on the pinned Socket.IO client installed on the disposable GitHub runner.
"use strict";
const fs = require("node:fs");
const crypto = require("node:crypto");
const assert = require("node:assert/strict");
const { io } = require("socket.io-client");

const mode = process.env.KUMA_MODE;
const target = process.env.KUMA_TARGET;
const port = Number(process.env.KUMA_LOCAL_PORT);
if (!["configure", "resume", "inspect", "verify", "pause"].includes(mode) ||
    !["ger1", "fin1"].includes(target) ||
    !Number.isInteger(port) || port < 1024 || port > 65535) {
    throw new Error("invalid target/mode/loopback port");
}
const read = (name) => fs.readFileSync(process.env[name], "utf8").trim();
const password = read("KUMA_PASSWORD_FILE");
const name = target === "ger1" ? "ProxySignal heartbeat (ger1)" : "Hostland HTTPS (fin1)";
const socket = io(`http://127.0.0.1:${port}`, {transports:["polling"],timeout:15000});
const call = (event, ...args) => new Promise((resolve,reject)=>{
    const timeout = setTimeout(()=>reject(new Error(event+" timeout")), 30000);
    socket.emit(event,...args,(result)=>{clearTimeout(timeout);resolve(result)});
});
const accepted = (event,result) => {
    if (!result || result.ok !== true) throw new Error(event+" rejected");
    return result;
};
async function main() {
    await new Promise((resolve,reject)=>{
        socket.once("connect",resolve);
        socket.once("connect_error",reject);
    });
    if (mode === "configure") {
        if ((await call("needSetup")) !== true) throw new Error("refusing to configure previously initialized Kuma");
        accepted("setup", await call("setup","proxysignal-admin",password));
    }
    accepted("login",await call("login",{username:"proxysignal-admin",password}));
    if (mode === "configure") {
        const webhookKey = read("KUMA_WEBHOOK_KEY_FILE");
        const notification = {
            name:"ProxySignal DOWN-only",
            type:"webhook",
            webhookURL:"http://down-only:8080/notify",
            httpMethod:"post",
            webhookContentType:"json",
            webhookAdditionalHeaders:JSON.stringify({"X-ProxySignal-Webhook-Key":webhookKey}),
            isDefault:false,
            applyExisting:false,
        };
        const notificationId = accepted("addNotification",
            await call("addNotification",notification,null)).id;
        assert(Number.isInteger(notificationId),"missing notification id");
        const monitor = {
            name, type:target==="ger1" ? "push" : "http",
            interval:target==="ger1" ? 360 : 300,
            retryInterval:60, maxretries:2, resendInterval:0,
            timeout:15, active:false,
            accepted_statuscodes:target==="ger1" ? [] : ["200-299"],
            method:"GET",
            conditions:[], kafkaProducerBrokers:[],
            kafkaProducerSaslOptions:{}, rabbitmqNodes:[],
            notificationIDList:{[notificationId]:true},
        };
        if (target === "ger1") monitor.pushToken = crypto.randomBytes(24).toString("base64url");
        else monitor.url = "https://panel.censor-amoroso.com/";
        const id = accepted("add", await call("add",monitor)).monitorID;
        assert(Number.isInteger(id),"missing monitor id");
        const info=accepted("getMonitor", await call("getMonitor",id)).monitor;
        assert(info.name===name && info.type===monitor.type && info.interval===monitor.interval,
            "monitor readback mismatch");
        if (target === "ger1") {
            assert(info.pushToken===monitor.pushToken,"push token mismatch");
            fs.writeFileSync(process.env.KUMA_PUSH_TOKEN_OUT, monitor.pushToken+"\n",{mode:0o600});
        }
        fs.writeFileSync(process.env.KUMA_MONITOR_ID_OUT, String(id)+"\n",{mode:0o600});
        console.log("PASS: "+target+" setup/auth/notification/monitor persisted (paused)");
    } else {
        const id=Number(read("KUMA_MONITOR_ID_FILE"));
        if(!Number.isInteger(id)||id<1)throw new Error("invalid monitor id");
        const info=accepted("getMonitor", await call("getMonitor",id)).monitor;
        assert(info.name===name,"monitor identity differs");
        if(target==="ger1" && process.env.KUMA_PUSH_TOKEN_OUT) {
            assert(typeof info.pushToken==="string" && /^[a-zA-Z0-9_-]{8,128}$/.test(info.pushToken),
                "missing or invalid Push token");
            fs.writeFileSync(process.env.KUMA_PUSH_TOKEN_OUT, info.pushToken+"\n",{mode:0o600});
        }
        if(mode==="pause") {
            accepted("pauseMonitor", await call("pauseMonitor",id));
            console.log("PASS: "+target+" monitor paused");
        } else if(mode==="verify") {
            const beats=accepted("getMonitorBeats",await call("getMonitorBeats",id,1));
            if(!Array.isArray(beats.data) || !beats.data.some(b=>b.status===1))
                throw new Error("no confirmed UP heartbeat");
            console.log("PASS: "+target+" has confirmed UP heartbeat");
        } else if(mode==="resume") {
            accepted("resumeMonitor", await call("resumeMonitor",id));
            console.log("PASS: "+target+" monitor activated");
        } else {
            console.log("PASS: "+target+" authenticated monitor readback");
        }
    }
}
main().catch(e=>{console.error("Kuma provisioning:",e.message);process.exitCode=1})
      .finally(()=>socket.disconnect());
