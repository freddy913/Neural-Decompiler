// multiply.c
#include <stdio.h>

/**
 * Eine kompliziertere Multiplikationsfunktion.
 * Wenn a negativ ist, wird eine spezielle "Bestrafung" angewendet,
 * ansonsten wird normal multipliziert.
 * Gibt das Ergebnis zurück.
 */
int complex_multiply(int a, int b) {
    int result;

    if (a < 0) {
        // "Bestrafungs"-Pfad: addiere, anstatt zu multiplizieren, und mache das Ergebnis negativ
        result = -(a + b);
    } else {
        // Normaler Pfad
        result = a * b;
    }

    return result;
}

// Erster Aufrufer (Caller)
void path_a(int x) {
    printf("Executing Path A...\n");
    int res = complex_multiply(x, 10); // Aufruf 1
    printf("Path A result: %d\n", res);
}

// Zweiter Aufrufer (Caller)
void path_b() {
    printf("Executing Path B...\n");
    int res = complex_multiply(-5, 7); // Aufruf 2
    printf("Path B result: %d\n", res);
}

// Dritter Aufrufer (Caller)
int path_c(int y, int z) {
    printf("Executing Path C...\n");
    int res = complex_multiply(y, z); // Aufruf 3
    printf("Path C result: %d\n", res);
    return res;
}

int main() {
    printf("--- Starting execution ---\n");
    
    // Rufe alle drei Pfade auf, die ihrerseits 'complex_multiply' aufrufen
    path_a(5);
    path_b();
    path_c(3, 4);

    printf("--- Execution finished ---\n");
    return 0;
}