import subprocess
import time
import numpy as np


flujos_totales = 7
num_conjuntos = 4

np.random.seed(2)
s = np.random.poisson(1.0,flujos_totales)
print s
np.random.seed(2)
duracion = np.random.exponential(60.0,num_conjuntos+1)
print duracion
flujosXconjunto = flujos_totales/num_conjuntos
for x in range(num_conjuntos+1):
  if x == num_conjuntos:
    print "HOLA!!!!!!!!!!!!!!!!!!!!!!!!!"
    flujosXconjunto = flujos_totales%num_conjuntos
  for y in range(flujosXconjunto):
    print x
    print y
    print duracion[x]
