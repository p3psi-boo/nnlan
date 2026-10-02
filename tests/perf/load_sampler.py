"""Optional bounded load-time diagnostics, identical for both compared binaries."""
import json
import threading
import time


class LoadSampler:
    def __init__(self, net, interval_ms):
        self.net = net
        self.interval = interval_ms / 1000
        self.samples = []
        self.error = None
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True)

    def run(self):
        start = time.monotonic()
        try:
            while not self.stop.is_set():
                sample = dict(at_seconds=time.monotonic() - start, nodes={})
                for node in self.net.names:
                    state = dict(qdisc=json.loads(self.net.ns(node, 'tc', '-s', '-j', 'qdisc', 'show', 'dev', 'wan').stdout),
                                 tcp=self.net.ns(node, 'ss', '-tin').stdout,
                                 udp=self.net.ns(node, 'ss', '-uamn').stdout)
                    if self.net.implementation == 'nnlan':
                        state['status'] = self.net.rpc(node, 'status')
                        state['tun_qdisc'] = json.loads(self.net.ns(node, 'tc', '-s', '-j', 'qdisc', 'show', 'dev', self.net.devices[node]).stdout)
                        state['tun_link'] = json.loads(self.net.ns(node, 'ip', '-s', '-j', 'link', 'show', 'dev', self.net.devices[node]).stdout)
                    sample['nodes'][node] = state
                if hasattr(self.net, 'router_name'):
                    sample['router'] = {dev: json.loads(self.net.router('tc', '-s', '-j', 'qdisc', 'show', 'dev', dev).stdout)
                                        for dev in ['left', 'right']}
                self.samples.append(sample)
                self.stop.wait(self.interval)
        except BaseException as error:
            self.error = error

    def __enter__(self):
        if self.interval:
            self.thread.start()
        return self

    def __exit__(self, kind, value, traceback):
        self.stop.set()
        if self.interval:
            self.thread.join()
        if self.error and kind is None:
            raise self.error
