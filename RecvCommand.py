from threading import Thread
import Queue

cola = Queue.Queue()

class RecvCommand(Thread):
	def __init__(self, socket):
		Thread.__init__(self)
		self.socket = socket
	def run(self):
		bo=0
		while (bo<=2):
			mensaje = self.socket.recv(1024)
			cola.put(mensaje)
			bo+=1
		print cola.get()
		print cola.get()
		print cola.get()
