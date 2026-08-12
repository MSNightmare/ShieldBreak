#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define ROWS 5
#define COLS 5

int main() {
    int matrix[ROWS][COLS];
    
    // Seed the random number generator using the current system time
    srand(time(NULL));
    
    // Populate the matrix with random integers from 1 to 100
    for (int i = 0; i < ROWS; i++) {
        for (int j = 0; j < COLS; j++) {
            matrix[i][j] = (rand() % 100) + 1;
        }
    }
    
    // Print the matrix to the screen
    printf("Generated Random Matrix:\n");
    for (int i = 0; i < ROWS; i++) {
        for (int j = 0; j < COLS; j++) {
            // \t creates tab spacing to keep columns aligned neatly
            printf("%d\t", matrix[i][j]); 
        }
        printf("\n"); // Newline after each row
    }
    
    return 0;
}
