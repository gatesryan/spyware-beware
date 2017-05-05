#include <stdio.h>
#include <stdlib.h>
#include <gtk/gtk.h>
#include <gdk/gdk.h>
#include <glib-object.h>
#include <pthread.h>
#include "monitor.h"
#include "helpers.h"
#include <glib.h>

void start_stop_monitoring_thread();
void * monitor_wrapper(void * args);


GtkBuilder *builder;
GObject *window;
GObject *button;
GObject *textview;
GObject *label;
GObject *port_entry;

pthread_t monitor_thread;


int monitoring = 0;

int main(int argc, char **argv)
{


    gtk_init (&argc, &argv);


    // gdk_threads_add_idle(monitor, NULL);

    builder = gtk_builder_new();
    gtk_builder_add_from_file(builder, "interface.ui", NULL);

    textview = gtk_builder_get_object(builder, "output");
    GtkTextBuffer * text_buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(textview));

    window = gtk_builder_get_object(builder, "window");
    g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);

    button = gtk_builder_get_object(builder, "button1");
    g_signal_connect_swapped(button, "clicked", G_CALLBACK(start_stop_monitoring_thread), text_buffer);

    port_entry = gtk_builder_get_object(builder, "port_entry");

    label = gtk_builder_get_object(builder, "status");


    char * output_str_array[65536];
    for (int i = 0; i < 65535; i++){

        char * output_str;
        asprintf(&output_str, "\nPort number %d: \nAddress: %s\n", i, " ");

        output_str_array[i] = output_str;
    }

    output_str_array[65535] = NULL;

    char * initial_output = g_strjoinv(NULL, output_str_array);
    // char * initial_output = join_strings(output_str_array);
    // gtk_text_buffer_set_text(text_buffer, initial_output, -1);

    gdk_threads_add_idle(update_text_view, NULL);
    gtk_main();


    return 0;
}

void start_stop_monitoring_thread(GtkWidget *widget, gpointer data)
{
    if (!monitoring){
        // Update label with status of what's happening to user
        gtk_label_set_text(GTK_LABEL(label), "Monitoring Network Traffic...");
        gtk_button_set_label(GTK_BUTTON(button), "Stop Monitoring");
        // void * buffer = (void *) buf;

        pthread_create(&monitor_thread, NULL, monitor_wrapper, widget);
        // pthread_detach(monitor_thread);
        monitoring = 1;
    }

    else{
        gtk_label_set_text(GTK_LABEL(label), "No Spyware Detected");
        gtk_button_set_label(GTK_BUTTON(button), "Start Monitoring");

        pthread_cancel(monitor_thread);
        monitoring = 0;
    }

    return;
}

void * monitor_wrapper(void * arg)
{
    GtkTextBuffer * buffer = GTK_TEXT_BUFFER(arg);
    int port_number = atoi(gtk_entry_get_text(GTK_ENTRY(port_entry)));

    monitor(buffer, port_number);
    return NULL;
}
