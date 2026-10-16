# Scenario: socket

**A TCP connection with slow replies.** A `client` thread sends one byte over a loopback TCP socket and waits for the answer; the `server` thread answers after 100 ms.

```powershell
Start-Process .\scenarios.exe -ArgumentList '--mode', 'socket', '--seconds', '15'
.\waitwhy.exe --name scenarios.exe --seconds 5
```

## What waitwhy reports

```
* Thread N (client) spent 9x% of the time waiting for the network, in scenarios!socket_round_trip.
```

## What it shows

Waits in `recv`, `WSARecv` or on an `\Device\Afd` file object are network waits. On a real network the other side is usually another machine, so waitwhy cannot show what it was doing; the time and the function in your code still tell you which request is slow.

## What CI checks

Hard: `(client) spent N% of the time waiting for the network, in scenarios!...socket_round_trip`.

Back to [all scenarios](README.md).
