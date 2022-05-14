# Proyecto 2 - Computación Paralela y Distribuida <br> Obtención de llaves de cifrado por Brutforce #
> María José Castro, Saúl Contreras, Gerardo Méndez

Obtención de llave de cifrado por medio de la técnica bruteforce. Implementa MPI para mejorar el desempeño.

### Ejecutar archivo secuencial

Compilar archivo
 ``` 
 g++ -o secuencial secuencial.cpp -lcryptopp 
 ```
Ejecutar archivo
 ``` 
 ./secuencial <Nombre del archivo.txt>
 ```


### Ejecutar archivo Paralelo

Compilar archivo
 ``` 
 mpic++ -o <object> -lcryptopp bruteforce.cpp
 ```
Ejecutar archivo
 ``` 
 mpirun -np <N> ./<object> <input_file> <keyword> <mode (1|2)>
 ```
