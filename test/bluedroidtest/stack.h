/*******************************************************************************
 *  Copyright (C) 2012-2013 Intel Mobile Communications GmbH
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at:
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 ******************************************************************************/


#ifndef STACK_H
#define STACK_H

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <errno.h>

#define INIT_OFFSET -100
#define INIT_IT_COUNT    -100

typedef struct __node_t
{
    long int offset;
    int it_count;
    struct __node_t* next;
} node_t;

node_t* create_node(long int offset, int it_count);
void push(node_t** head, node_t* new_node);
node_t* pop(node_t** head);
int is_stack_empty(node_t* head);
void init_stack(node_t** head);

static void display(node_t* head);

node_t* create_node(long int offset, int it_count)
{
    node_t* new_node = (node_t*) malloc(sizeof (node_t));
    if (new_node == NULL)
    {
        printf("ERROR: Malloc failure\n");
        return NULL;
    }
    new_node->offset = offset;
    new_node->it_count = it_count;
    new_node->next = NULL;
    return new_node;
}

void init_stack(node_t** head)
{
    if (*head != NULL)
    {
        printf("ERROR: init_stack(): head is not NULL\n");
        return;
    }
    *head = create_node(INIT_OFFSET, INIT_IT_COUNT);
}

int is_stack_empty(node_t* head)
{
    if (head->offset == INIT_OFFSET && head->it_count == INIT_IT_COUNT)
    {
        printf("Stack empty\n");
        return 0;
    }
    return 1;
}
void push(node_t** head, node_t* new_node)
{
    if (*head == NULL || new_node == NULL)
        return;
    new_node->next = *head;
    *head = new_node;
}

node_t* pop(node_t** head)
{
    node_t* temp = *head;
    if (temp == NULL)
        return NULL;
    if (is_stack_empty(*head) == 0)
        return NULL;
    *head = (*head)->next;
    return temp;
}
#endif
#if 0
static void display(node_t* head)
{
    node_t* temp = head;
    printf("%s\n", __func__);
    while(temp)
    {
        printf("offset:%ld it_count:%d\n", temp->offset, temp->it_count);
        temp = temp->next;
    }
}

static void popall(node_t** head)
{
    node_t* temp;
    while(is_stack_empty(*head) != 0)
    {
        temp = pop(head);
        printf("POP node: offset:%ld it_count:%d\n", temp->offset, temp->it_count);
        free(temp);
    }
    printf("ALL POP DONE\n");
}

void f()
{
    printf("doing operation.....\n");
}
void readfile()
{
    node_t *stack = NULL;
    node_t *temp;
    init_stack(&stack);
    static const char filename[] = "file.txt";
    long int offset;
    int it_count;
    FILE *file = fopen ( filename, "r" );
    if (file != NULL)
    {
        char line [ 128 ]; /* or other suitable maximum line size */
        char cmd [64], arg[64];

        while ( fgets ( line, sizeof line, file ) != NULL ) /* read a line */
        {
            sscanf(line, "%s %s", cmd, arg);
            printf("cmd:%s: arg:%s:\n", cmd, arg);
            if (strcmp(cmd, "repeat") == 0)
            {
                it_count = atoi(arg);
                if (it_count != 0)
                {
                    offset = ftell(file);
                    printf("repeat call: offset:%ld it_count:%d\n", offset, it_count);
                    push(&stack, create_node(offset, it_count));
                }
                if (strcmp(arg, "end") == 0)
                {
                    temp = pop(&stack);
                    if (temp != NULL)
                    {
                        if (temp->it_count > 1)
                        {
                            printf("repeat end call. seek to:%ld it_count:%d\n", temp->offset, temp->it_count);
                            fseek (file, temp->offset, SEEK_SET);
                            push(&stack, create_node(temp->offset, temp->it_count-1));
                        }
                        free(temp);
                    }
                }
            }
        }
    fclose ( file );
    }
    else
    {
        perror ( filename );
    }
}

int main()
{
    readfile();
    return 0;
}
#endif
