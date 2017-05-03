#include <stdio.h>
#include <gtk/gtk.h>
#include "monitor.h"
#include <glib-object.h>
#include <pthread.h>

void start_monitoring_thread();
void * monitor_wrapper(void * args);


static void print_hello(GtkWidget *widget, gpointer data)
{
    g_print("Hello World\n");
}

static void activate(GtkApplication* app, gpointer user_data)
{
    GtkWidget* window;
    GtkWidget* button;
    GtkWidget* button_box;

    window = gtk_application_window_new(app);
    gtk_window_set_title (GTK_WINDOW(window), "Spyware Beware");
    gtk_window_set_default_size (GTK_WINDOW(window), 200, 200);
    gtk_widget_show_all(window);



    button_box = gtk_button_box_new(GTK_ORIENTATION_HORIZONTAL);
    gtk_container_add(GTK_CONTAINER(window), button_box);

    button = gtk_button_new_with_label("Hello World!");
    g_signal_connect(button, "clicked", G_CALLBACK(print_hello), NULL);
    g_signal_connect_swapped(button, "clicked", G_CALLBACK(gtk_widget_destroy), window);
    gtk_container_add(GTK_CONTAINER(button_box), button);

    gtk_widget_show_all(window);

}

int main(int argc, char **argv)
{



    GtkBuilder *builder;
    GObject *window;
    GObject *button;
    GObject *textview;
    GObject *label;

    gtk_init (&argc, &argv);

    builder = gtk_builder_new();
    gtk_builder_add_from_file(builder, "interface.ui", NULL);

    window = gtk_builder_get_object(builder, "window");
    g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);

    button = gtk_builder_get_object(builder, "button1");
    g_signal_connect(button, "clicked", G_CALLBACK(start_monitoring_thread), NULL);

    // textview = gtk_builder_get_object(builder, "output");

    label = gtk_builder_get_object(builder, "status");
    //
    // PangoAttrList* attributes = pango_attr_list_new();
    //
    // PangoAttribute * new_weight = pango_attr_weight_new(PANGO_WEIGHT_BOLD);
    // pango_attr_list_change(attributes, new_weight);
    //
    // PangoAttribute *new_size = pango_attr_size_new(25000);
    // pango_attr_list_change(attributes, new_size);

    // gtk_label_set_attributes(label, attributes);
    //
    // gtk_label_set_text(label, "HELLLLO!");

    // gtk_label_set_markup (GTK_LABEL (label), "<span font=\"22\">Hello</span>");


    gtk_main();

    // GtkApplication* app;
    // int status;
    //
    // app = gtk_application_new ("org.gtk.example", G_APPLICATION_FLAGS_NONE);
    // g_signal_connect(app, "activate", G_CALLBACK(activate), NULL);
    // status = g_application_run(G_APPLICATION(app), argc, argv);
    // g_object_unref(app);


    return 0;
}

void start_monitoring_thread()
{
    pthread_t monitor_thread;
    pthread_create(&monitor_thread, NULL, monitor_wrapper, NULL);
    pthread_detach(monitor_thread);
    return;
}

void * monitor_wrapper(void * args)
{
    monitor();
    return NULL;
}
